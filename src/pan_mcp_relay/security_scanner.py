# Copyright (c) 2025, Palo Alto Networks
#
# Licensed under the Polyform Internal Use License 1.0.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
#
# https://polyformproject.org/licenses/internal-use/1.0.0
# (or)
# https://github.com/polyformproject/polyform-licenses/blob/76a278c4/PolyForm-Internal-Use-1.0.0.md
#
# As far as the law allows, the software comes as is, without any warranty
# or condition, and the licensor will not be liable to you for any damages
# arising out of these terms or the use or nature of the software, under
# any kind of legal claim.
import datetime
import functools
import getpass
import hashlib
import http
import json
import os
import ssl
import sys
import uuid
from enum import StrEnum
from json.decoder import JSONDecodeError
from typing import Any

import httpx
import tenacity
import yaml
from aisecurity.scan.asyncio.scanner import ScanResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, validate_call
from tenacity import stop_after_attempt, wait_fixed

from . import utils
from ._version import __version__
from .configuration import McpRelayConfig
from .constants import (
    MCP_RELAY_NAME,
    SYNC_SCAN_PATH,
)
from .exceptions import McpRelayScanError, McpRelaySecurityBlockError, ScanApiAuthenticationError, ScanApiInternalError

log = utils.get_logger(__name__)


class APIAuth(httpx.Auth):
    @validate_call
    def __init__(self, api_key: str | SecretStr | None):
        if isinstance(api_key, SecretStr):
            api_key = api_key.get_secret_value()
        if not isinstance(api_key, str):
            raise TypeError("API key must be a string")
        self.api_key = api_key

    def auth_flow(self, request):
        # Send the request, with a custom `X-Authentication` header.
        request.headers["x-pan-token"] = self.api_key
        yield request


class ScanSource(StrEnum):
    call_tool = "call_tool"
    prepare_tool = "prepare_tool"


class ScanType(StrEnum):
    scan_request = "scan_request"
    scan_response = "scan_response"
    scan_tool = "scan_tool"


class SecurityScanner(BaseModel):
    config: McpRelayConfig
    client: httpx.AsyncClient | None = Field(default=None, init=False)
    user: str | None = Field(default=None, init=False)

    model_config = ConfigDict(arbitrary_types_allowed=True)

    __hash__ = object.__hash__

    def model_post_init(self, context: Any, /) -> None:
        if self.config.use_system_ca:
            import truststore

            log.info("Using system truststore")
            ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        elif self.config.custom_ca_file:
            log.info(f"Using custom CA file: {self.config.custom_ca_file}")
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        else:
            import certifi

            log.debug("Using default SSL/TLS trust configuration")
            # Use `SSL_CERT_FILE` or `SSL_CERT_DIR` if configured.
            # Otherwise default to certifi.
            ctx = ssl.create_default_context(
                cafile=os.getenv("SSL_CERT_FILE", certifi.where()),
                capath=os.getenv("SSL_CERT_DIR"),
            )
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        auth = APIAuth(api_key=self.config.api_key.get_secret_value())
        log.debug("Creating httpx client")
        limits = httpx.Limits(keepalive_expiry=300)
        transport = httpx.AsyncHTTPTransport(verify=ctx, retries=3)
        self.client = httpx.AsyncClient(
            verify=ctx,
            http2=True,
            auth=auth,
            base_url=self.config.api_endpoint,
            timeout=30,
            max_redirects=0,
            limits=limits,
            transport=transport,
            headers={"User-Agent": user_agent()},
        )

        self.user = getpass.getuser()

    async def shutdown(self) -> None:
        log.debug("Shutting down security scanner")
        await self.client.aclose()
        log.debug("Security scanner shutdown complete")

    @functools.cache
    def ai_profile(self) -> dict[str, str]:
        if isinstance(self.config.ai_profile, uuid.UUID):
            ai_profile = dict(profile_id=str(self.config.ai_profile))
        else:
            try:
                ai_profile_id = uuid.UUID(self.config.ai_profile)
                ai_profile = dict(profile_id=str(ai_profile_id))
            except (ValueError, TypeError):
                ai_profile_name = self.config.ai_profile
                ai_profile = dict(profile_name=ai_profile_name)
        ai_profile_text = yaml.safe_dump(ai_profile)
        log.info(f"Using AI Profile: {ai_profile_text}")
        return ai_profile

    @functools.cache
    def metadata(self) -> dict[str, str]:
        metadata = dict(app_name="pan-mcp-relay")
        if self.user is not None:
            metadata["user"] = self.user
        return metadata

    @validate_call
    @tenacity.retry(
        reraise=True,
        retry=tenacity.retry_if_not_exception_type((ScanApiAuthenticationError, McpRelaySecurityBlockError)),
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
    )
    async def scan(
        self,
        source: ScanSource,
        scan_type: ScanType,
        prompt: str,
        response: str | None = None,
    ) -> ScanResponse | None:
        scan_label = f"mcp-relay.{scan_type}"
        if source:
            scan_label += f".{source}"

        utc_dt = datetime.datetime.now(datetime.UTC)  # UTC time
        dt: datetime.datetime = utc_dt.astimezone()  # local time

        tr_id = scan_label + dt.isoformat()
        ai_profile = self.ai_profile()
        metadata = self.metadata()
        scan_content = dict(prompt=prompt)
        if response:
            scan_content["response"] = response

        body = dict(tr_id=tr_id, ai_profile=ai_profile, metadata=metadata, contents=[scan_content])
        body_json = json.dumps(body)
        body_checksum = hashlib.sha256(body_json.encode("utf-8")).hexdigest()[:8]
        log.debug(f"{scan_label}: POST {self.client.base_url}+{SYNC_SCAN_PATH} (checksum: {body_checksum})")
        try:
            scan_result: httpx.Response = await self.client.post(
                SYNC_SCAN_PATH,
                json=body,
            )
            scan_result.raise_for_status()
            scan_response_data = scan_result.json()
            scan_response = ScanResponse(**scan_response_data)
        except httpx.HTTPStatusError as se:
            response_data: dict | None = None
            response_body: bytes | None = None
            api_error: str | None = None
            try:
                response_data = se.response.json()
            except JSONDecodeError:
                response_body = se.response.content
            if response_data:
                api_error = response_data.get("error", {}).get("message", None)
            if api_error is None:
                api_error = "Unknown Error"
                log.debug(response_body)
            api_error = f"{api_error} ({se.response.status_code})"
            if se.response.status_code in [http.HTTPStatus.UNAUTHORIZED, http.HTTPStatus.FORBIDDEN]:
                raise ScanApiAuthenticationError(api_error) from se
            elif se.response.status_code > 500:
                raise ScanApiInternalError(api_error) from se
            log.exception(f"Failed to execute scan request: {se}")
            raise McpRelayScanError("Security Scan Failed") from se
        except JSONDecodeError as de:
            log.exception("Failed to parse scan response")
            raise McpRelayScanError("Security Scan Failed JSON Decoding") from de
        except ValidationError as ve:
            log.exception("Failed to validate scan response schema")
            raise McpRelaySecurityBlockError("Security Scan Failed") from ve

        action = scan_response.action

        log.debug(scan_response.model_dump(exclude_none=True, exclude_unset=True, exclude_defaults=True))

        log_msg = f"{scan_label}: action={action} (checksum: {body_checksum})"

        if action == "allow":
            log.info(
                f"[bold green]{log_msg}[/bold green] scan_id={scan_response.scan_id}",
                extra=dict(markup=True),
            )
        elif action == "block":
            log.warning(
                f"[bold red]{log_msg}[/bold red] scan_id={scan_response.scan_id}",
                extra=dict(markup=True),
            )
            raise McpRelaySecurityBlockError(f"{scan_type} from {source} was blocked")
        else:
            log.error(
                f"[bold orange]UNKNOWN ACTION:{action}, {scan_type} from {source}[/bold orange]",
                extra=dict(markup=True),
            )

        return scan_response


@functools.cache
def user_agent() -> str:
    py_version = ".".join([str(v) for v in sys.version_info[0:3]])

    return f"{MCP_RELAY_NAME}/{__version__} ({sys.platform}, {py_version})"
