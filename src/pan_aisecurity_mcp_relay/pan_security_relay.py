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

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import mcp.types as types
import uvicorn
import yaml
from mcp.server.lowlevel import Server
from mcp.server.sse import SseServerTransport
from mcp.server.stdio import stdio_server
from pydantic import BaseModel, Field, validate_call
from starlette.applications import Starlette
from starlette.routing import Route

from . import utils
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
    McpRelaySecurityBlockError,
    McpRelayServerNotFoundError,
    McpRelayToolExecutionError,
    McpRelayToolNotFoundError,
)
from .security_scanner import ScanSource, ScanType, SecurityScanner
from .tool import InternalTool, ToolState
from .tool_registry import ToolRegistry

__posixpath__ = Path(__file__).resolve()

log = utils.get_logger(__name__)


class PanSecurityRelay(BaseModel):
    """Main relay server class that orchestrates tool execution and security scanning."""

    config: McpRelayConfig
    mcp_servers_config: dict[str, McpServerType]
    servers: dict[str, DownstreamMcpClient] = Field(default_factory=dict, init=False)
    tool_registry: ToolRegistry | None = Field(default=None, init=False)
    scanner: SecurityScanner | None = Field(default=None, init=False)

    def model_post_init(self, context: Any, /) -> None:
        self.tool_registry: ToolRegistry = ToolRegistry(config=self.config)
        if len(self.mcp_servers_config) == 0:
            raise McpRelayConfigurationError("No MCP servers configured.")
        elif len(self.mcp_servers_config) >= self.config.max_mcp_servers:
            raise McpRelayConfigurationError(
                f"MCP servers configuration limit exceeded, maximum allowed: {self.config.max_mcp_servers}"
            )
        self.scanner = SecurityScanner(config=self.config)

    async def initialize(self) -> None:
        """Initialize the relay server and register all tools."""
        try:
            # Configure downstream MCP servers from configuration
            await self._update_tool_registry()

            log.info("MCP relay server initialized successfully.")
        except McpRelayBaseError as relay_error:
            log.error(f"MCP Relay initialization error: {relay_error}")
            raise relay_error
        except Exception as other_error:
            log.exception(f"Failed to initialize MCP relay server, error: {other_error}")
            raise
        log.info("Initialized MCP Relay server successfully.")

    async def shutdown(self) -> None:
        for server in self.servers.values():
            await server.cleanup()
        await self.scanner.shutdown()

    async def _update_tool_registry(self) -> None:
        """Update the tool registry with tools from all configured servers."""
        log.info("event=update_tool_registry")

        # Collect individual server tool lists
        full_tool_list = await self.initialize_downstream_mcp_servers()

        # Validate the total number of tools against max downstream tools
        self._validate_tool_limits(full_tool_list)

        # Dedup full list, disable dup name tools
        self._disable_tools_with_duplicate_names(full_tool_list)

        # Update tool registry
        self.tool_registry.update_registry(full_tool_list)

    async def initialize_downstream_mcp_servers(self) -> dict[str, InternalTool]:
        """Collect tools from all configured downstream servers."""
        full_tool_list: dict[str, InternalTool] = {}

        server_init_tasks: dict[str, asyncio.Task] = {}
        list_tool_tasks: dict[str, asyncio.Task] = {}
        prepare_tool_tasks: defaultdict[str, dict[str, asyncio.Task]] = defaultdict(dict)
        initialize_exceptions: dict[str, Exception] = {}
        async with asyncio.TaskGroup() as tg:
            for server_name in self.mcp_servers_config.keys():
                server_config = self.mcp_servers_config[server_name]
                self.servers[server_name] = DownstreamMcpClient(name=server_name, config=server_config)
                server_init_tasks[server_name] = tg.create_task(self.servers[server_name].initialize())

        async with asyncio.TaskGroup() as tg:
            for server_name, server_init_task in server_init_tasks.items():
                initialized = server_init_task.result()
                if not initialized:
                    initialize_exceptions[server_name] = McpRelayInternalError(
                        f"Failed to initialize server: {server_name}"
                    )
                    continue

                server = self.servers[server_name]
                list_tool_tasks[server_name] = tg.create_task(server.list_tools())

        if initialize_exceptions:
            raise ExceptionGroup("Failed to initialize MCP Server(s)", *initialize_exceptions)

        async with asyncio.TaskGroup() as tg:
            for server_name, list_tool_task in list_tool_tasks.items():
                server_tools: dict[str, types.Tool] = list_tool_task.result()
                for tool_name, tool in server_tools.items():
                    prepare_tool_tasks[server_name][tool_name] = tg.create_task(self._prepare_tool(server_name, tool))
        for server_name, server_tool_tasks in prepare_tool_tasks.items():
            for tool_task in server_tool_tasks.values():
                tool: InternalTool = tool_task.result()
                full_tool_list[tool.server_tool_name] = tool

        return full_tool_list

    async def _prepare_tool(self, server_name: str, tool: types.Tool) -> InternalTool:
        """Process and prepare tools from a specific server."""
        state = ToolState.ENABLED
        internal_tool = InternalTool(
            server_name=server_name,
            state=state,
            **tool.model_dump(exclude_unset=True, exclude_none=True),
        )
        known_tool = self.tool_registry.get_tool_by_hash(internal_tool.sha256_hash)
        if known_tool is None:
            # Security scan
            tool_info_dict = internal_tool.model_dump(mode="json", exclude_none=True, exclude_unset=True)
            tool_info_yaml = yaml.dump(tool_info_dict, sort_keys=False)
            log.debug(f"Scanning Tool Description:\n{tool_info_yaml!s}")
            try:
                await self.scanner.scan(
                    source=ScanSource.prepare_tool, scan_type=ScanType.scan_tool, prompt=tool_info_yaml, response=None
                )
            except McpRelaySecurityBlockError:
                internal_tool.state = ToolState.DISABLED_SECURITY_RISK
            except McpRelayScanError:
                log.error(f"Security Scan Failed for server: {server_name}")
                server = self.servers[server_name]
                await server.cleanup()
                internal_tool.state = ToolState.DISABLED_ERROR
                raise
            else:
                internal_tool.state = ToolState.ENABLED
        else:
            internal_tool.state = known_tool.state

        return internal_tool

    @validate_call
    def _validate_tool_limits(self, tools: dict[str, InternalTool]) -> None:
        """Additional validation of tool limits and constraints."""
        if len(tools) > self.config.max_mcp_tools:
            raise McpRelayConfigurationError(f"Tools limit exceeded, maximum allowed: {self.config.max_mcp_tools}")

    @validate_call
    def _disable_tools_with_duplicate_names(self, tools: dict[str, InternalTool]):
        """Identify and disable tools with duplicate names."""
        tools_by_name_only: dict[str, InternalTool] = {}
        duplicate_tools: list[str] = []
        for server_tool_name, tool in tools.items():
            if tool.state == ToolState.ENABLED:
                if tool.name in tools_by_name_only:
                    duplicate_tools.append(tool.server_tool_name)
                    duplicate_tools.append(tools_by_name_only[tool.name].server_tool_name)
                else:
                    tools_by_name_only[tool.name] = tool
        if len(duplicate_tools) > 0:
            log.warning(f"Duplicate tool names: {', '.join(duplicate_tools)}")

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
            description=(
                "This tool is intended for debugging purposes and provides detailed information about "
                "configured downstream servers."
            ),
            inputSchema={"type": "object", "properties": {}},
        )

        return available_tool_list

    @validate_call
    async def _handle_tool_execution(self, name: str, arguments: dict) -> types.CallToolResult:
        """Handle tool execution requests."""
        input_data = {name: arguments}
        input_text = yaml.safe_dump(input_data, sort_keys=False)

        # Scan the request for security issues
        # Raises McpRelaySecurityBlockError if content was blocked by AI Profile
        await self.scanner.scan(ScanSource.call_tool, ScanType.scan_request, input_text)

        # Handle special case for relay info tool
        if name == TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO:
            return await self._handle_list_downstream_servers_info()

        # Get the server for this tool
        available_tools = self.tool_registry.get_available_tools()

        if name not in available_tools:
            raise McpRelayToolNotFoundError(f"Unknown tool: {name}")

        tool = available_tools[name]

        # Execute the tool on the downstream server
        result = await self._execute_on_server(tool.server_name, name, arguments)

        result_content = self.extract_text_content(result.content)

        await self.scanner.scan(ScanSource.call_tool, ScanType.scan_response, input_text, str(result_content))

        if result.isError:
            raise McpRelayToolExecutionError(str(result.content))

        return result

    def extract_text_content(self, content: Any) -> Any:
        """
        Extract text from various MCP content types.

        Args:
            content: The content to extract text from

        Returns:
            Extracted text content or JSON representation
        """
        # Handle list of content items
        if isinstance(content, list):
            if len(content) == 1:
                return self.extract_text_content(content[0])
            return [self.extract_text_content(item) for item in content]

        # Handle specific MCP content types
        if isinstance(content, (types.EmbeddedResource, types.ImageContent, types.TextContent)):
            return content.model_dump_json()

        # Handle objects with text attribute
        if hasattr(content, "text"):
            return content.text

        # Handle objects with input_value attribute
        if hasattr(content, "input_value"):
            return content.input_value

        # Return as-is for other types
        return content

    async def _handle_list_downstream_servers_info(self) -> types.CallToolResult:
        log.info(f"Current tool registry status: {self.tool_registry.get_registry_stats()}")
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=self.tool_registry.get_server_tool_map_json())],
            isError=False,
        )

    @validate_call
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

    @staticmethod
    async def run_stdio_server(app: Server) -> None:
        """Run the server with stdio transport."""
        log.info("Starting server with stdio transport.")
        log.info("Press Ctrl-D to exit.")

        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options(), raise_exceptions=True)

    @staticmethod
    async def run_sse_server(app: Server, host: str, port: int) -> None:
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
