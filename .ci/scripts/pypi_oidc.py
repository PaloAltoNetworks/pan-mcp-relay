#!/usr/bin/env -S uv run --script
# PEP 723 Inline Script Metadata
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "rich",
#     "google-auth",
#     "httpx[http2]",
#     "requests",
#     "rich",
#     "truststore",
# ]#
# ///
import argparse
import asyncio
import logging
import ssl
from pathlib import Path

import google.auth
import google.auth.impersonated_credentials
import google.auth.transport.requests
import httpx
import requests
import rich.logging
import truststore

DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


pypi_indexes = dict(main="https://pypi.org", test="https://test.pypi.org")

google_auth_transport_session = requests.Session()
google_auth_requests_transport = google.auth.transport.requests.Request()

__self__ = Path(__file__)
log = logging.getLogger(__self__.stem)


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--service-account-email",
        "--sa",
        dest="sa",
        help="Email address of Service Account to Impersonate",
        required=True,
    )
    parser.add_argument(
        "--index",
        "--repo",
        "-r",
        choices=["main", "test"],
        help="PyPi Index",
        required=True,
    )
    parser.add_argument("--output", "-o", help="Optional Output File")

    log_opts = parser.add_mutually_exclusive_group()

    log_opts.add_argument(
        "--log-level",
        choices=["ERROR", "WARNING", "INFO", "DEBUG"],
        help="Logging Legel",
    )
    log_opts.add_argument("--debug", action="store_true", help="Enable Debug Logging")
    return parser.parse_args()


async def pypi_audience(argv, client: httpx.AsyncClient) -> str:
    index_url = pypi_indexes.get(argv.index)
    res = await client.get(f"{index_url}/_/oidc/audience")
    data = res.json()
    audience = data.get("audience")
    log.info(f"Using audience: {audience}")
    return audience


async def main():
    argv = parse_args()
    if argv.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif argv.log_level:
        logging.getLogger().setLevel(logging.getLevelName(argv.log_level))

    # Use system certificate stores.
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client = httpx.AsyncClient(verify=ctx, http2=True)

    audience: str = await pypi_audience(argv, client)

    credentials, project_id = google.auth.default()  # noqa RUF059 - keep unused project_id variable
    impersonated_access_token_creds = get_access_token(argv, credentials)
    impersonated_id_token_creds = get_id_token(
        source_credentials=impersonated_access_token_creds,
        audience=audience,
    )
    id_token = impersonated_id_token_creds.token

    access_token_info = await get_access_token_info(client=client, access_token=impersonated_access_token_creds.token)
    if "sub" in access_token_info:
        log.info(f"Service Account Subject (sub): {access_token_info.get('sub')}")
    if "aud" in access_token_info:
        log.info(f"Service Account Audience (aud): {access_token_info.get('aud')}")
    if "email" in access_token_info:
        log.info(f"Service Account Email (email): {access_token_info.get('email')}")

    pypi_token = await get_pypi_token(argv, client, id_token)

    if argv.output and argv.output.strip() != "-":
        output_path = Path(argv.output)
        output_path.write_text(id_token)
        log.info(f"Wrote {len(pypi_token)} bytes to {output_path}")
    else:
        print(pypi_token)


async def get_access_token_info(client: httpx.AsyncClient, access_token: str) -> dict | None:
    url = f"https://oauth2.googleapis.com/tokeninfo?access_token={access_token}"

    headers = {"Content-Type": "application/json"}
    res = await client.get(url=url, headers=headers)
    if res.status_code != 200:
        log.error(f"Failed to get Access Token Info: HTTP {res.status_code} {res.reason_phrase}")
        return None
    return res.json()


class PyPiTokenMintException(Exception):
    pass


async def get_pypi_token(argv, client: httpx.AsyncClient, id_token: str):
    """Get a PyPi API Token using a Google OAuth2 ID Token"""
    # Equivilent cURL:
    r"""
    resp=$(curl -X POST https://pypi.org/_/oidc/mint-token \
        -d "{\"token\": \"${oidc_token}\"}")

    api_token=$(jq -r '.token' <<< "${resp}")
    """

    index_url = pypi_indexes.get(argv.index)
    url = f"{index_url}/_/oidc/mint-token"
    req_data = dict(token=id_token)
    res = await client.request("POST", url=url, json=req_data)
    res_data = res.json()
    if res.status_code != 200:
        log.error(f"pypi mint-token failed: HTTP {res.status_code} {res.reason_phrase}: {res_data}")
        raise PyPiTokenMintException(f"{res.status_code} {res.reason_phrase}")
    if "token" not in res_data:
        log.error("Missing token in PyPi Response")
        raise PyPiTokenMintException("No Token Returned")

    return res_data.get("token")


def get_access_token(argv, credentials) -> google.auth.impersonated_credentials.Credentials:
    target_principal = argv.sa
    target_credentials = google.auth.impersonated_credentials.Credentials(
        source_credentials=credentials,
        target_principal=target_principal,
        target_scopes=DEFAULT_SCOPES,
    )
    target_credentials.refresh(google_auth_requests_transport)
    if not target_credentials.valid:
        log.error(f"Failed to impersonate service account: {target_principal}")
        return target_credentials

    target_credentials.get_cred_info()
    return target_credentials


def get_id_token(
    source_credentials: google.auth.impersonated_credentials.Credentials,
    audience: str,
) -> google.auth.impersonated_credentials.IDTokenCredentials:
    id_token_credentials = google.auth.impersonated_credentials.IDTokenCredentials(
        target_credentials=source_credentials,
        target_audience=audience,
        include_email=True,
    )
    id_token_credentials.refresh(google_auth_requests_transport)
    if not id_token_credentials.valid:
        log.error("Failed to refresh ID Token")
    return id_token_credentials


if __name__ == "__main__":
    console = rich.console.Console(stderr=True)
    logging.basicConfig(format="%(message)s", level=logging.INFO, handlers=[rich.logging.RichHandler(console=console)])
    logging.getLogger("httpx").setLevel(logging.WARNING)
    asyncio.run(main())
