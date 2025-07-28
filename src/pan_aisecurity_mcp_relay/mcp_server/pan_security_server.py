#!/usr/bin/env -S uv run fastmcp run -t sse # noqa: CPY001
"""
Palo Alto Networks AI Runtime Security (AIRS) API - Model Context Protocol (MCP) Server Example

This is an example MCP Server demonstrating the use of the AI Runtime Security API Intercept as MCP Tools.

The server exposes the AIRS API functionality of as various MCP tools:
- Inline Prompt/Response Scanning
- Batch (Asynchronous) Scanning for collections of Prompts/Responses
- Retrieval of Scan Results and Scan Threat Reports
"""
# PEP 723 Inline Script Metadata
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pan-aisecurity",
#     "fastmcp",
#     "python-dotenv",
# ]#
# ///

import asyncio
import itertools
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import dotenv
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from typing_extensions import Any, TypedDict

import aisecurity
from aisecurity.constants.base import (
    MAX_NUMBER_OF_BATCH_SCAN_OBJECTS,
    MAX_NUMBER_OF_SCAN_IDS,
    MAX_NUMBER_OF_REPORT_IDS,
)
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

ai_profile: AiProfile
scanner = Scanner()


@asynccontextmanager
async def mcp_lifespan_manager(*args, **kwargs) -> AsyncIterator[Any]:
    """Starlette Lifespan Context Manager

    This is required to close the shared aiohttp connection pool on server shutdown.
    """
    yield
    await scanner.close()


# Create the MCP Server with the lifespan context manager
mcp = FastMCP("aisecurity-scan-server", lifespan=mcp_lifespan_manager)


class SimpleScanContent(TypedDict):
    """SimpleScanContent is a TypedDict representing a greatly simplified ScanRequestContentsInner object."""

    prompt: str | None
    response: str | None


def pan_init():
    """Initialize the AI Runtime Security SDK (e.g. with your API Key).

    NOTE: You probably DON'T want to run aisecurity.init() at the module top-level
    to ensure the MCP Server Runtime Environment has a chance to set up environment
    variables _before_ this function is run.
    """
    global ai_profile

    # Load Environment variables from .env if available
    dotenv.load_dotenv()
    # Make this function run only once
    if getattr(pan_init, "__completed__", False):
        return
    if ai_profile_name := os.getenv("PANW_AI_PROFILE_NAME"):
        ai_profile = AiProfile(profile_name=ai_profile_name)
    elif ai_profile_id := os.getenv("PANW_AI_PROFILE_ID"):
        ai_profile = AiProfile(profile_id=ai_profile_id)
    else:
        raise ToolError(
            "Missing AI Profile Name (PANW_AI_PROFILE_NAME) or AI Profile ID (PANW_AI_PROFILE_ID)"
        )
    aisecurity.init(
        api_key=os.getenv(
            "PANW_AI_SEC_API_KEY"
        ),  # Optional - shows default fallback behavior
        api_endpoint=os.getenv(
            "PANW_AI_SEC_API_ENDPOINT"
        ),  # Optional - shows default fallback behavior
    )
    setattr(pan_init, "__completed__", True)


@mcp.tool()
async def pan_inline_scan(
    prompt: str | None = None, response: str | None = None
) -> ScanResponse:
    """Submit a single Prompt and/or Model-Response (Scan Content) to be scanned synchronously.

    This is a blocking operation - the function will not return until the scan is complete
    or a timeout, (e.g. as configured in the AI Profile), is breached.

    Returns a complete Scan Response, notably the category (benign/malicious) and action (allow/block).

    See also: https://pan.dev/prisma-airs/api/airuntimesecurity/scan-sync-request/
    """
    pan_init()
    if not prompt and not response:
        raise ToolError(
            f"Must provide at least one of prompt ({prompt}) and/or response ({response})."
        )
    scan_response = await scanner.sync_scan(
        ai_profile=ai_profile,
        content=Content(
            prompt=prompt,
            response=response,
        ),
    )
    return scan_response


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
        async_scan_batches.append(
            [
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
            ]
        )

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
    batch_results: list[list[ScanIdResult]] = await asyncio.gather(
        *tasks, return_exceptions=True
    )

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
    batch_results: list[list[ThreatScanReportObject]] = await asyncio.gather(
        *tasks, return_exceptions=True
    )

    # flatten nested list
    return safe_flatten(batch_results)


def maybe_monkeypatch_itertools_batched():
    # monkeypatch itertools on python < 3.12
    # This is required for python versions before 3.12, since itertools.batched was
    # added in python 3.12, and is required for the above functions to work.
    if sys.version_info.minor < 12:

        def batched(iterable, n, *, strict=False):
            if n < 1:
                raise ValueError("n must be at least one")
            iterator = iter(iterable)
            while batch := tuple(itertools.islice(iterator, n)):
                if strict and len(batch) != n:
                    raise ValueError("batched(): incomplete batch")
                yield batch

        setattr(itertools, "batched", batched)


if __name__ == "__main__":
    pan_init()
    maybe_monkeypatch_itertools_batched()
    asyncio.run(mcp.run_async())
