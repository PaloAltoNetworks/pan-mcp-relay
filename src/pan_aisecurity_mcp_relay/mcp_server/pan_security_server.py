#!/usr/bin/env -S uv run fastmcp run -t sse # noqa: CPY001
"""
Palo Alto Networks AI Runtime Security (AIRS) API - Model Context Protocol (MCP) Server Example

This is an example MCP Server demonstrating the use of the AI Runtime Security API Intercept as MCP Tools.

The server exposes the AIRS API functionality as several MCP tools:
- Inline Prompt/Response Scanning
- Batch (Asynchronous) Scanning for collections of Prompts/Responses
- Retrieval of Scan Results and Scan Threat Reports
"""

# PEP 723 Inline Script Metadata
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pan-aisecurity",
#     "mcp",
#     "python-dotenv",
# ]#
# ///

import asyncio
import functools
import itertools
import logging
import os
import sys
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import aisecurity
import dotenv
import rich
import rich.logging
from aisecurity.constants.base import (
    MAX_NUMBER_OF_BATCH_SCAN_OBJECTS,
    MAX_NUMBER_OF_REPORT_IDS,
    MAX_NUMBER_OF_SCAN_IDS,
)
from aisecurity.exceptions import AISecSDKException
from aisecurity.generated_openapi_client import (
    AsyncScanObject,
    AsyncScanResponse,
    ScanIdResult,
    ScanRequest,
    ScanRequestContentsInner,
    ScanResponse,
    ThreatScanReportObject,
)
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.asyncio.scanner import Scanner
from aisecurity.scan.models.content import Content
from aisecurity.utils import safe_flatten
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from typing_extensions import TypedDict

from pan_aisecurity_mcp_relay.constants import ENV_AI_PROFILE, ENV_API_ENDPOINT, ENV_API_KEY

log = logging.getLogger("pan-mcp-relay.pan_security_server")


def setup_logging():
    """Initialize logging."""
    stderr = rich.console.Console(stderr=True)
    logging.basicConfig(
        level=logging.NOTSET,
        format="%(message)s)",
        handlers=[rich.logging.RichHandler(rich_tracebacks=True, console=stderr)],
    )


ai_profile: AiProfile
scanner: Scanner


@asynccontextmanager
async def mcp_lifespan_manager(*args, **kwargs) -> AsyncIterator[Any]:
    """Starlette Lifespan Context Manager

    This is required to close the shared aiohttp connection pool on server shutdown.
    """
    try:
        yield
    finally:
        # Cleanup on shutdown
        await scanner.close()


# Create the MCP Server with the lifespan context manager
mcp = FastMCP("aisecurity-scan-server", lifespan=mcp_lifespan_manager)


class SimpleScanContent(TypedDict):
    """SimpleScanContent is a TypedDict representing a greatly simplified ScanRequestContentsInner object."""

    prompt: str | None
    response: str | None


@functools.cache
def pan_init():
    """Initialize the AI Runtime Security SDK (e.g. with your API Key).

    NOTE: You probably DON'T want to run aisecurity.init() at the module top-level
    to ensure the MCP Server Runtime Environment has a chance to set up environment
    variables _before_ this function is run.
    """
    global ai_profile, scanner

    # Load Environment variables from .env if available
    dotenv.load_dotenv()

    api_key = os.getenv(ENV_API_KEY)
    api_endpoint = os.getenv(ENV_API_ENDPOINT)
    aiprofile = os.getenv(ENV_AI_PROFILE)
    err_msgs = []
    if not api_key:
        err_msg = f"Missing Environment Variable with API Key ({ENV_API_KEY})"
        err_msgs.append(err_msg)
        log.error(err_msg)
    if not api_endpoint:
        err_msg = f"Missing Environment Variable with API Endpoint ({ENV_API_ENDPOINT})"
        err_msgs.append(err_msg)
        log.error(err_msg)
    if not aiprofile:
        err_msg = f"Missing Environment Variable with AI Profile Name or ID ({ENV_AI_PROFILE})"
        err_msgs.append(err_msg)
        log.error(err_msg)
    if err_msgs:
        raise ToolError(", ".join(err_msgs))

    ai_profile_name = ai_profile_id = None
    try:
        ai_profile_id = uuid.UUID(aiprofile)
        ai_profile = AiProfile(profile_id=ai_profile_id)
    except (ValueError, TypeError):
        ai_profile_name = aiprofile

    if ai_profile_id:
        ai_profile = AiProfile(profile_id=ai_profile_id)
    elif ai_profile_name:
        ai_profile = AiProfile(profile_name=ai_profile_name)
    else:
        raise ToolError(f"Missing Environment Variable with AI Profile Name or ID ({ENV_AI_PROFILE})")

    aisecurity.init(
        api_key=api_key,
        api_endpoint=api_endpoint,
    )
    scanner = Scanner()


@mcp.tool()
async def pan_inline_scan(prompt: str | None = None, response: str | None = None) -> ScanResponse:
    """Submit a single Prompt and/or Model-Response (Scan Content) to be scanned synchronously.

    This is a blocking operation - the function will not return until the scan is complete
    or a timeout, (e.g. as configured in the AI Profile), is breached.

    Returns a complete Scan Response, notably the category (benign/malicious) and action (allow/block).

    See also: https://pan.dev/prisma-airs/api/airuntimesecurity/scan-sync-request/
    """
    pan_init()
    if not prompt and not response:
        raise ToolError(f"Must provide at least one of prompt ({prompt}) and/or response ({response}).")
    try:
        scan_response = await scanner.sync_scan(
            ai_profile=ai_profile,
            content=Content(
                prompt=prompt,
                response=response,
            ),
        )
        return scan_response
    except AISecSDKException as e:
        raise ToolError(str(e))


@mcp.tool()
async def pan_batch_scan(
    scan_contents: list[SimpleScanContent],
) -> list[AsyncScanResponse]:
    """Submit multiple Scan Contents containing prompts/model-responses for asynchronous (batch) scanning.

    Automatically splits requests into batches of 5, which are submitted concurrently.

    Returns a list of AsyncScanResponse objects, each includes a scan_id and report_id,
    which can be used to retrieve scan results after the asynchronous scans are complete.

    See also: https://pan.dev/prisma-airs/api/airuntimesecurity/scan-async-request/
    """
    global ai_profile

    pan_init()
    # build the AsyncScanContent object
    async_scan_batches: list[list[AsyncScanObject]] = []

    req_id = 0
    # Split into batches
    for batch in itertools.batched(scan_contents, MAX_NUMBER_OF_BATCH_SCAN_OBJECTS):
        async_scan_batches.append([
            AsyncScanObject(
                req_id=(req_id := req_id + 1),
                scan_req=ScanRequest(
                    ai_profile=ai_profile,
                    contents=[
                        ScanRequestContentsInner(
                            prompt=sc.get("prompt"),
                            response=sc.get("response"),
                        )
                    ],
                ),
            )
            for sc in batch
        ])

    # Process each batch concurrently via asyncio
    scan_coros = [scanner.async_scan(batch) for batch in async_scan_batches]
    bulk_scan_results: list[AsyncScanResponse] = await asyncio.gather(*scan_coros)

    return bulk_scan_results


@mcp.tool()
async def pan_get_scan_results(scan_ids: list[str]) -> list[ScanIdResult]:
    """Retrieve Scan Results with a list of Scan IDs.

    A Scan ID is a UUID string.

    See also: https://pan.dev/prisma-airs/api/airuntimesecurity/get-scan-results-by-scan-i-ds/
    """
    pan_init()
    request_batches: list[list[str]] = []
    for batch in itertools.batched(scan_ids, MAX_NUMBER_OF_SCAN_IDS):
        request_batches.append(list(batch))

    # Process each batch concurrently via asyncio
    tasks = [scanner.query_by_scan_ids(batch) for batch in request_batches]
    batch_results: list[list[ScanIdResult]] = await asyncio.gather(*tasks, return_exceptions=True)

    # flatten nested list
    return safe_flatten(batch_results)


@mcp.tool()
async def pan_get_scan_reports(report_ids: list[str]) -> list[ThreatScanReportObject]:
    """Retrieve Scan Reports with a list of Scan Report IDs.

    A Scan Report ID is a Scan ID (UUID) prefixed with "R".

    See also: https://pan.dev/prisma-airs/api/airuntimesecurity/get-threat-scan-reports/
    """
    pan_init()

    request_batches: list[list[str]] = []
    for batch in itertools.batched(report_ids, MAX_NUMBER_OF_REPORT_IDS):
        request_batches.append(list(batch))

    # Process each batch concurrently via asyncio
    tasks = [scanner.query_by_report_ids(batch) for batch in request_batches]
    batch_results: list[list[ThreatScanReportObject]] = await asyncio.gather(*tasks, return_exceptions=True)

    # flatten nested list
    return safe_flatten(batch_results)


def entrypoint():
    """CLI script entrypoint"""
    pan_init()
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    sys.exit(entrypoint())
