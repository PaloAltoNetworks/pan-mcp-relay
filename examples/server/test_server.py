"""
Test MCP Server

A Model Context Protocol (MCP) server that provides testing tools
such as echo, random text, latency simulation, passthrough, and
intentional failure. Supports both stdio and SSE transport methods.
"""

import anyio
import click
import logging
import random
import string
import asyncio
from typing import List

from mcp.types import Tool, TextContent
from mcp.server.lowlevel import Server

logging.basicConfig(level=logging.INFO)

@click.command()
@click.option("--port", default=8001, help="Port to listen on for SSE")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default="stdio",
    help="Transport type",
)
def main(port: int, transport: str) -> int:
    """
    Main entry point for the Test MCP server.

    Creates and configures an MCP server with basic testing tools,
    then runs it using the specified transport method.
    """
    app = Server("test-mcp-server")

    @app.call_tool()
    async def call_tool(name: str, arguments: dict) -> List[TextContent]:
        if name == "echo_tool":
            text = arguments.get("text", "No input provided")
            return [TextContent(type="text", text=f"[Echo] {text}")]

        elif name == "random_text_tool":
            length = int(arguments.get("length", 10))
            random_text = ''.join(random.choices(string.ascii_letters, k=length))
            return [TextContent(type="text", text=f"[Random] {random_text}")]

        elif name == "latency_simulator_tool":
            delay = float(arguments.get("delay", 1.0))
            await asyncio.sleep(delay)
            return [TextContent(type="text", text=f"[LatencySimulator] Slept for {delay} seconds")]

        elif name == "passthrough_tool":
            return [TextContent(type="text", text="[Passthrough] OK")]

        elif name == "failing_tool":
            raise ValueError("[FailingTool] Intentional failure for testing purposes.")

        else:
            raise ValueError(f"Unknown tool: {name}")

    @app.list_tools()
    async def list_tools() -> List[Tool]:
        return [
            Tool(
                name="echo_tool",
                description="Echo back the provided text.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to echo back."}
                    },
                },
            ),
            Tool(
                name="random_text_tool",
                description="Generate random text of specified length.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "length": {"type": "integer", "description": "Length of random text."}
                    },
                },
            ),
            Tool(
                name="latency_simulator_tool",
                description="Simulate latency by sleeping for specified seconds.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "delay": {"type": "number", "description": "Seconds to sleep."}
                    },
                },
            ),
            Tool(
                name="passthrough_tool",
                description="Basic passthrough tool that always returns OK.",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="failing_tool",
                description="Always fails with an error for testing purposes.",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    if transport == "sse":
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Mount, Route
        import uvicorn

        sse = SseServerTransport("/messages/")

        async def handle_sse(request):
            async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
                await app.run(streams[0], streams[1], app.create_initialization_options())

        starlette_app = Starlette(
            debug=True,
            routes=[
                Route("/sse", endpoint=handle_sse),
                Mount("/messages/", app=sse.handle_post_message),
            ],
        )

        uvicorn.run(starlette_app, host="0.0.0.0", port=port)
    else:
        from mcp.server.stdio import stdio_server

        async def arun():
            async with stdio_server() as streams:
                await app.run(streams[0], streams[1], app.create_initialization_options())

        anyio.run(arun)
    return 0

if __name__ == "__main__":
    main()
