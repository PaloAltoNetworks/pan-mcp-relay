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
"""
MCP Server Setup and Run Functions
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import mcp.server
import starlette
import uvicorn
from mcp import stdio_server
from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.responses import Response
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from .. import utils
from ..configuration import McpRelayConfig

log = utils.get_logger(__name__)


async def run_stdio_server(_: McpRelayConfig, server: mcp.server.Server) -> None:
    """Run the server with stdio transport."""
    log.info("Starting server with stdio transport.")
    log.info("Press Ctrl-D to exit.")

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
            raise_exceptions=False,
            stateless=True,
        )


async def run_http_server(config: McpRelayConfig, starlette_app: Starlette) -> None:
    """Run the server using StreamableHTTP transport."""
    host = str(config.host)
    port = config.port
    config = uvicorn.Config(
        starlette_app,
        host=host,
        port=port,
        log_level=config.log_level_name().lower(),
    )
    server = uvicorn.Server(config)
    log.info(f"Starting HTTP Server on {host}:{port}")
    log.info("Press Ctrl-C to exit.")
    await server.serve()


def setup_sse_server(
    config: McpRelayConfig,
    server: mcp.server.Server,
    lifespan: starlette.types.StatelessLifespan,
) -> Starlette:
    """Set up a Starlette HTTP Server for MCP SSE Transport"""
    sse = SseServerTransport("/messages")

    async def _handle_sse(scope: Scope, receive: Receive, send: Send):
        async with sse.connect_sse(
            scope,
            receive,
            send,
        ) as streams:
            await server.run(
                streams[0],
                streams[1],
                server.create_initialization_options(),
            )
        return Response()

    starlette_app = Starlette(
        debug=config.debug_enabled(),
        routes=[
            Route("/sse", endpoint=_handle_sse),
            Route("/messages", endpoint=sse.handle_post_message, methods=["POST"]),
        ],
        lifespan=lifespan,
    )
    return starlette_app


def setup_http_server(
    config: McpRelayConfig,
    server: mcp.server.Server,
    lifespan: starlette.types.StatelessLifespan,
) -> Starlette:
    """Set up a Starlette HTTP Server for MCP Streamable HTTP Transport"""
    session_manager = StreamableHTTPSessionManager(
        app=server,
        # TODO(rb): Do we need this?
        event_store=None,
        # TODO(rb): Add this as a configuration/flag
        json_response=False,
    )

    # ASGI handler for streamable HTTP connections
    async def handle_streamable_http(scope: Scope, receive: Receive, send: Send) -> None:
        """MCP Streamable HTTP Request Handler"""
        await session_manager.handle_request(scope, receive, send)

    @asynccontextmanager
    async def http_server_lifespan(_: Starlette) -> AsyncIterator[None]:
        """Context manager for session manager."""
        async with lifespan(server):
            async with session_manager.run():
                yield

    # Create an ASGI application using the transport
    starlette_app = Starlette(
        debug=config.debug_enabled(),
        routes=[
            starlette.routing.Mount("/mcp", app=handle_streamable_http),
        ],
        lifespan=http_server_lifespan,
    )

    return starlette_app
