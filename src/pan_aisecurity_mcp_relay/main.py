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

import argparse
import asyncio
import logging
import sys

from .constants import (
    MAX_DOWNSTREAM_SERVERS_DEFAULT,
    MAX_DOWNSTREAM_TOOLS_DEFAULT,
    SECURITY_ENV_KEYS,
    TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT,
    TransportType,
)
from .pan_security_relay import PanSecurityRelay


async def main() -> int | None:
    """Main entry point for the MCP relay server."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-file", type=str, required=True, help="Path to config file")
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse"],
        help="Transport protocol to use",
    )
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host for SSE server")
    parser.add_argument("--port", type=int, default=8000, help="Port for SSE server")
    parser.add_argument(
        "--tool-registry-cache-expiry-in-seconds",
        type=int,
        required=False,
        default=TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT,
        help="Downsteam mcp tool registry cache expiry",
    )
    parser.add_argument(
        "--max-mcp-servers",
        type=int,
        required=False,
        default=MAX_DOWNSTREAM_SERVERS_DEFAULT,
        help="Max number of downstream servers",
    )
    parser.add_argument(
        "--max-mcp-tools",
        type=int,
        required=False,
        default=MAX_DOWNSTREAM_TOOLS_DEFAULT,
        help="Max number of MCP tools",
    )
    parser.add_argument("--PANW_AI_SEC_API_KEY", type=str, help="PANW AI Security API Key")
    parser.add_argument("--PANW_AI_SEC_API_ENDPOINT", type=str, help="PANW AI Security API Endpoint")
    parser.add_argument("--PANW_AI_PROFILE_NAME", type=str, help="PANW AI Profile Name")
    parser.add_argument("--PANW_AI_PROFILE_ID", type=str, help="PANW AI Profile ID")

    args = parser.parse_args()

    security_scanner_config: dict[str, str] = {
        k: v for k in SECURITY_ENV_KEYS if (v := getattr(args, k, None)) is not None and str(v).strip() != ""
    }

    # Initialize the relay server
    config_path = args.config_file
    tool_registry_cache_expiry = args.tool_registry_cache_expiry_in_seconds
    max_downstream_servers = args.max_mcp_servers
    max_downstream_tools = args.max_mcp_tools
    relay_server = PanSecurityRelay(
        config_path,
        security_scanner_config,
        tool_registry_cache_expiry,
        max_downstream_servers,
        max_downstream_tools,
    )
    await relay_server.initialize()

    # Create and run the MCP server
    app = await relay_server.launch_mcp_server()

    if args.transport == TransportType.STDIO:
        await relay_server.run_stdio_server(app)
    elif args.transport == TransportType.SSE:
        await relay_server.run_sse_server(app, args.host, args.port)


def entrypoint():
    logging.basicConfig(
        level=logging.INFO,
        format="[MCP Relay] %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    asyncio.run(main())


if __name__ == "__main__":
    sys.exit(entrypoint())
