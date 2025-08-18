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
MCP Relay Security Server

This module implements a security-enhanced MCP (Model Context Protocol) relay server that acts as an intermediary
between clients and downstream MCP servers. It provides comprehensive security scanning for both incoming requests
and outgoing responses, tool registry management with caching, and centralized orchestration of multiple downstream
MCP servers.

Key Features:
- Security scanning of tool requests and responses using integrated AI security services
- Tool registry with deduplication, caching, and state management
- Support for multiple downstream MCP servers with configurable limits
- Hidden mode support for bypassing security scans on trusted servers
- Automatic tool discovery and registration from configured downstream servers

Classes:
    PanSecurityRelay: Main relay server class that orchestrates tool execution and security scanning

Functions:
    main: Entry point that configures and starts the MCP relay server

The relay server connects to downstream MCP servers, scans all tool interactions for security
risks, and provides a unified interface for clients while enforcing security policies and resource limits.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any

import mcp.types as types
import uvicorn
from mcp.server.lowlevel import Server
from mcp.server.sse import SseServerTransport
from mcp.server.stdio import stdio_server
from pydantic import BaseModel
from starlette.applications import Starlette
from starlette.routing import Route

from .configuration import McpRelayConfig, McpServerType
from .constants import (
    MCP_RELAY_NAME,
    TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO,
)
from .downstream_mcp_client import DownstreamMcpClient
from .exceptions import (
    McpRelayBaseError,
    McpRelayConfigurationError,
    McpRelayInternalError,
    McpRelayScanError,
    McpRelayServerNotFoundError,
    McpRelayToolExecutionError,
    McpRelayToolNotFoundError,
)
from .security_scanner import ScanRequestType
from .tool import InternalTool, ToolState
from .tool_registry import ToolRegistry

__posixpath__ = Path(__file__).resolve()


from pan_aisecurity_mcp_relay import utils

log = utils.get_logger(__name__)


class PanSecurityRelay(BaseModel):
    """Main relay server class that orchestrates tool execution and security scanning."""

    servers: dict[str, DownstreamMcpClient] = {}
    config: McpRelayConfig
    mcp_servers_config: dict[str, McpServerType]
    tool_registry: ToolRegistry | None = None

    def model_post_init(self, context: Any, /) -> None:
        self.tool_registry: ToolRegistry = ToolRegistry(self.config.tool_registry_cache_ttl)

    async def initialize(self) -> None:
        """Initialize the relay server and register all tools."""
        log.info("Initializing pan security relay...")
        try:
            # Load configuration and validate server configurations
            self._load_config()

            # Configure downstream MCP servers from configuration
            await self._update_tool_registry()

            log.info("MCP relay server initialized successfully.")
        except McpRelayBaseError as relay_error:
            log.error(f"MCP Relay initialization error: {relay_error}")
            raise relay_error
        except Exception as other_error:
            log.exception(f"Failed to initialize MCP relay server, error: {other_error}")
            raise

    async def shutdown(self) -> None:
        await self.scanner.shutdown()

    def _load_config(self) -> dict[str, Any]:
        """Validate MCP Server Configuration Limits"""
        mcp_servers = self.mcp_servers_config
        if isinstance(mcp_servers, dict):
            if len(mcp_servers.items()) == 0:
                raise McpRelayConfigurationError("No MCP servers configured.")
            if len(mcp_servers.items()) >= self.max_downstream_servers:
                raise McpRelayConfigurationError(
                    f"MCP servers configuration limit exceeded, maximum allowed: {self.max_downstream_servers}"
                )
            return mcp_servers
        else:
            raise McpRelayConfigurationError("Unexpected configuration format for servers.")

    async def _update_tool_registry(self) -> None:
        """Update the tool registry with tools from all configured servers."""
        log.info("event=update_tool_registry")
        servers_config = self._load_config()

        # Collect individual server tool lists
        full_tool_list = await self._collect_tools_from_servers(servers_config)

        # Validate the total number of tools against max downstream tools
        self._validate_tool_limits(full_tool_list)

        # Dedup full list, disable dup name tools
        self._disable_tools_with_duplicate_names(full_tool_list)

        # Update tool registry
        self.tool_registry.update_registry(full_tool_list)

    async def _collect_tools_from_servers(self, servers_config) -> list[InternalTool]:
        """Collect tools from all configured downstream servers."""
        full_tool_list: list[InternalTool] = []
        for server_name, server_config in servers_config.items():
            server = DownstreamMcpClient(server_name, server_config)
            initialized = await server.initialize()
            if not initialized:
                raise McpRelayInternalError(f"Failed to initialize server: {server_name}")
            self.servers[server_name] = server

            # Register all tools from this server
            server_tools = await server.list_tools()
            hidden_mode_enabled = server_config.get("env", {}).get("hidden_mode") == "enabled"
            try:
                await self._prepare_tool(server_name, server_tools, hidden_mode_enabled, full_tool_list)
            except McpRelayScanError:
                log.error(f"Security Scan Failed for server: {server_name}")
                raise
            finally:
                await server.cleanup()
        return full_tool_list

    def _validate_tool_limits(self, tools: list[InternalTool]) -> None:
        """Additional validation of tool limits and constraints."""
        if len(tools) > self.max_downstream_tools:
            raise McpRelayConfigurationError(f"Tools limit exceeded, maximum allowed: {self.max_downstream_tools}")

    async def _prepare_tool(
        self,
        server_name: str,
        server_tools: list[types.Tool],
        hidden_mode_enabled: bool,
        full_tool_list: list[InternalTool],
    ):
        """Process and prepare tools from a specific server."""
        for server_tool in server_tools:
            state = ToolState.ENABLED
            internal_tool = InternalTool(
                name=server_tool.name,
                description=server_tool.description,
                inputSchema=deepcopy(server_tool.inputSchema),
                annotations=server_tool.annotations,
                server_name=server_name,
                state=state,
            )
            # Skip scan for hidden servers
            if hidden_mode_enabled:
                internal_tool.state = ToolState.DISABLED_HIDDEN_MODE
            else:
                exist_tool = self.tool_registry.get_tool_by_hash(internal_tool.sha256_hash)
                if exist_tool is None:
                    # Security scan
                    log.info(f"Scan tool info: {server_tool.model_dump()!s}")
                    tool_scan_result = await self.scanner.scan_tool(server_tool)
                    if self.scanner.should_block(tool_scan_result):
                        internal_tool.state = ToolState.DISABLED_SECURITY_RISK
                    else:
                        internal_tool.state = ToolState.ENABLED
                else:
                    internal_tool.state = exist_tool.state
            full_tool_list.append(internal_tool)

    def _disable_tools_with_duplicate_names(self, tools: list[InternalTool]):
        """Identify and disable tools with duplicate names."""
        name_to_tool_dict: dict[str, InternalTool] = {}
        for tool in tools:
            if tool.state == ToolState.ENABLED:
                if tool.name in name_to_tool_dict:
                    log.info(f"Tool '{tool.name}' already in dict, skipping or updating...")
                    name_to_tool_dict[tool.name].state = ToolState.DISABLED_DUPLICATE
                    tool.state = ToolState.DISABLED_DUPLICATE
                else:
                    name_to_tool_dict[tool.name] = tool
        duplicate_tool_names = [
            f"{tool.server_name}:{tool.name}" for tool in tools if tool.state == ToolState.DISABLED_DUPLICATE
        ]
        if len(duplicate_tool_names) > 0:
            log.warning(f"Duplicate tool names: {duplicate_tool_names}")

    async def mcp_server(self) -> Server:
        """Create and configure the MCP Relay Server with tool handlers.

        This is the MCP Server for the MCP Relay itself, and is what MCP Clients connect to and use.
        """
        from ._version import __version__

        app = Server(
            name=MCP_RELAY_NAME,
            version=__version__,
        )

        @app.list_tools()
        async def list_tools() -> list[types.Tool]:
            log.info("list_tools()")
            try:
                return list((await self._handle_list_tools()).values())
            except McpRelayBaseError as relay_error:
                log.exception("MCP Relay list tools failed")
                raise relay_error
            except Exception as e:
                log.exception(f"Error listing tools: {e}")
                raise McpRelayInternalError("Failed to list tools") from e

        @app.call_tool()
        async def call_tool(
            name: str, arguments: dict
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            log.info(f"call_tool({name})")
            try:
                result = await self._handle_tool_execution(name, arguments)
                if result.isError:
                    raise McpRelayToolExecutionError(str(result.content))
                return result.content
            except McpRelayBaseError as relay_error:
                log.exception("MCP Relay call tool error")
                raise relay_error
            except Exception as e:
                log.exception(f"call_tool({name}) failed")
                raise McpRelayInternalError(f"Failed to call tool {name}: {e}") from e

        return app

    async def _handle_list_tools(self) -> dict[str, types.Tool]:
        """Handle the list_tools request."""
        available_tool_list: dict[str, types.Tool] = {}
        if self.tool_registry.is_registry_outdated():
            await self._update_tool_registry()

        # Process each tool
        for tool in self.tool_registry.get_available_tools():
            log.debug(f"Processing tool: {tool.name}")
            available_tool_list[tool.name] = tool.to_mcp_tool()
            log.debug(f"Tool {tool.name}: State={tool.state}, Total tools={len(available_tool_list)}")

        # Add the relay info tool
        available_tool_list[TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO] = types.Tool(
            name=TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO,
            description="This tool is intended for debugging purposes and provides detailed information about configured downstream servers.",
            inputSchema={"type": "object", "properties": {}},
        )

        return available_tool_list

    async def _handle_tool_execution(self, name: str, arguments: dict) -> types.CallToolResult:
        """Handle tool execution requests."""
        input_text = f"{name}: {arguments!s}"

        # Scan the request for security issues
        # Raises McpRelaySecurityBlockError if content was blocked by AI Profile
        await self.scanner.scan("call_tool", input_text)

        # Handle special case for relay info tool
        if name == TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO:
            return await self._handle_list_downstream_servers_info()

        # Get the server for this tool
        available_tools = self.tool_registry.get_available_tools()
        target_tool = None
        for tool in available_tools:
            if tool.name == name:
                target_tool = tool
                break

        if not target_tool:
            raise McpRelayToolNotFoundError(f"Unknown tool: {name}")

        # Execute the tool on the downstream server
        result = await self._execute_on_server(target_tool.server_name, name, arguments)

        result_content = self.scanner.pan_security_server.extract_text_content(result.content)

        await self.scanner.scan("call_tool", ScanRequestType.scan_response, input_text, str(result_content))

        if result.isError:
            raise McpRelayToolExecutionError(str(result.content))

        return result

    async def _handle_list_downstream_servers_info(self) -> types.CallToolResult:
        log.info(f"Current tool registry status: {self.tool_registry.get_registry_stats()}")
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=self.tool_registry.get_server_tool_map_json())],
            isError=False,
        )

    async def _execute_on_server(self, server_name: str, tool_name: str, arguments: dict) -> types.CallToolResult:
        """Execute a tool on a specific downstream server."""
        if server_name not in self.servers:
            raise McpRelayServerNotFoundError(f"Server not found: {server_name}")

        server = self.servers[server_name]
        initialized = await server.initialize()
        if not initialized:
            raise McpRelayInternalError(f"Server not initialized: {server_name}")

        try:
            log.info(f"Executing: {server_name} - {tool_name} - {arguments}")
            result = await server.execute_tool(tool_name, arguments)
            return result
        finally:
            await server.cleanup()

    async def run_stdio_server(self, app: Server) -> None:
        """Run the server with stdio transport."""
        log.info("Starting server with stdio transport.")
        log.info("Press Ctrl-D to exit.")

        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    async def run_sse_server(self, app: Server, host: str, port: int) -> None:
        """Run the server with SSE transport."""
        log.info(f"Starting server with SSE transport on {host}:{port}")
        log.info("Press Ctrl-D to exit.")

        sse_transport = SseServerTransport("/messages")
        # Use the wrapper classes for the endpoints
        sse_endpoint = SseEndpoint(sse_transport, app)
        messages_endpoint = MessagesEndpoint(sse_transport)

        starlette_app = Starlette(
            routes=[
                Route("/sse", endpoint=sse_endpoint),
                Route("/messages", endpoint=messages_endpoint, methods=["POST"]),
            ]
        )

        uvicorn_config = uvicorn.Config(starlette_app, host=host, port=port)
        uvicorn_server = uvicorn.Server(uvicorn_config)
        await uvicorn_server.serve()

    @asynccontextmanager
    async def server_lifespan(self, _server: Server) -> AsyncIterator[Any]:
        """Manage server startup and shutdown lifecycle."""
        # Initialize resources on startup
        await self.initialize()
        try:
            yield
        finally:
            # Clean up on shutdown
            await self.shutdown()


class SseEndpoint:
    """ASGI endpoint for handling the main SSE connection."""

    def __init__(self, transport: SseServerTransport, app: Server):
        self.transport = transport
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        async with self.transport.connect_sse(scope, receive, send) as streams:
            await self.app.run(streams[0], streams[1], self.app.create_initialization_options())


class MessagesEndpoint:
    """ASGI endpoint for handling incoming POST messages over SSE."""

    def __init__(self, transport: SseServerTransport):
        self.transport = transport

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        await self.transport.handle_post_message(scope, receive, send)
