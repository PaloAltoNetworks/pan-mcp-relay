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
import functools
from collections import deque
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import anyio
import mcp
import mcp.types as types
import yaml
from mcp.client.session_group import ServerParameters
from mcp.server.lowlevel import Server
from pydantic import validate_call

from . import utils
from .client import RelayClient
from .client.session_group import RelaySessionGroup
from .configuration import McpRelayConfig, McpServerType
from .constants import (
    MCP_RELAY_NAME,
)
from .exceptions import (
    McpRelayBaseError,
    McpRelayConfigurationError,
    McpRelayInternalError,
    McpRelayScanError,
    McpRelaySecurityBlockError,
    McpRelayToolExecutionError,
    McpRelayToolNotFoundError,
)
from .security_scanner import ScanSource, ScanType, SecurityScanner
from .tool import InternalTool, ToolState
from .tool_registry import ToolRegistry

__posixpath__ = Path(__file__).resolve()

log = utils.get_logger(__name__)


class PanSecurityRelay:
    """Main relay server class that orchestrates tool execution and security scanning."""

    config: McpRelayConfig
    mcp_servers_config: dict[str, McpServerType]
    relay_clients: dict[str, RelayClient]
    client_sessions: dict[str, mcp.ClientSession]
    tool_registry: ToolRegistry | None
    scanner: SecurityScanner | None
    _shutdown_lock: asyncio.Lock
    _exit_stack: AsyncExitStack
    _client_session_group: RelaySessionGroup | None

    def __init__(self, config: McpRelayConfig, mcp_servers_config: dict[str, McpServerType]) -> None:
        self.config = config
        self.mcp_servers_config = mcp_servers_config
        self.relay_clients = {}
        self.client_sessions = {}
        self.tool_registry: ToolRegistry = ToolRegistry(config=self.config)
        self.scanner = SecurityScanner(config=self.config)
        self._shutdown_lock = asyncio.Lock()
        self._exit_stack = AsyncExitStack()

        client_session_group = RelaySessionGroup(exit_stack=self._exit_stack)
        self._client_session_group = client_session_group
        self._exit_stack.enter_async_context(client_session_group.__aenter__)
        self._exit_stack.push_async_exit(client_session_group.__aexit__)

        if len(self.mcp_servers_config) == 0:
            raise McpRelayConfigurationError("No MCP servers configured.")
        elif len(self.mcp_servers_config) >= self.config.max_mcp_servers:
            raise McpRelayConfigurationError(
                f"MCP servers configuration limit exceeded, maximum allowed: {self.config.max_mcp_servers}"
            )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> bool | None:
        """Closes session exit stacks and main exit stack upon completion."""
        await self.shutdown()

    async def _initialize(self) -> None:
        """Initialize the relay server and register all tools."""
        try:
            # Configure downstream MCP servers from configuration
            await self._update_tool_registry()

            log.info("MCP relay server initialized successfully.")
        except McpRelayBaseError as relay_error:
            log.error(f"MCP Relay initialization error: {relay_error}")
            raise relay_error
        except Exception as e:
            log.exception(f"Failed to initialize MCP relay server, error: {e}")
            raise

        log.info("Initialized MCP Relay server successfully.")

    @functools.cache
    async def shutdown(self) -> None:
        log.info("Shutting down MCP Relay server")
        async with self._shutdown_lock:
            await self.scanner.shutdown()
            await self._exit_stack.aclose()
        log.debug("MCP Relay server shutdown complete")

    @asynccontextmanager
    async def server_lifespan(self, _server: Server) -> AsyncIterator[Any]:
        """Manage server startup and shutdown lifecycle."""
        # Initialize resources on startup
        await self._initialize()
        yield
        # await self.shutdown()
        # try:
        #     yield
        # except anyio.get_cancelled_exc_class():
        #     with anyio.CancelScope(shield=True):
        #         await self.shutdown()
        #     raise

    async def _update_tool_registry(self) -> None:
        """Update the tool registry with tools from all configured servers."""
        log.info("event=update_tool_registry")

        try:
            # Collect individual server tool lists
            await self._initialize_relay_clients()
            tools: dict[str, types.Tool] = self._client_session_group.tools
            all_tools: dict[str, InternalTool] = await self._scan_tools(tools)

        except Exception:
            log.exception("Error updating tool registry")
            raise
        # Validate the total number of tools against max downstream tools
        self._validate_tool_limits(all_tools)

        # Update tool registry
        self.tool_registry.update_registry(all_tools)

    async def _initialize_relay_clients(self):
        """Collect tools from all configured downstream servers."""
        client_sessions: deque[tuple[str, mcp.ClientSession]] = deque()

        async def _connect_to_server(server_name: str, server_params: ServerParameters):
            try:
                session = await self._client_session_group.connect_to_server_with_name(server_name, server_params)
                client_sessions.append((server_name, session))
            except mcp.McpError as e:
                log.error(f"Failed starting server: {server_name}: {e}")
                log.error(server_params)

        for server_name, server_config in self.mcp_servers_config.items():
            client = RelayClient(name=server_name, config=server_config)
            self.relay_clients[server_name] = client
            await _connect_to_server(server_name, client.get_server_params())

        for server_name, session in client_sessions:
            self.client_sessions[server_name] = session

    @validate_call
    async def _scan_tools(self, tools: dict[str, types.Tool]) -> dict[str, InternalTool]:
        scanned_tools: deque[tuple[str, InternalTool]] = deque()

        async def _scan_tool(tool_name: str, tool: types.Tool):
            internal_tool = await self._scan_tool(tool_name, tool)
            scanned_tools.append((tool_name, internal_tool))

        async with anyio.create_task_group() as tg:
            for tool_name, tool in tools.items():
                tg.start_soon(_scan_tool, tool_name, tool)
        return {n: t for n, t in scanned_tools}

    @validate_call
    async def _scan_tool(self, tool_name: str, tool: types.Tool) -> InternalTool:
        """Process and prepare tools from a specific server."""
        state = ToolState.ENABLED
        internal_tool = InternalTool(
            state=state,
            name=tool_name,
            **tool.model_dump(exclude_unset=True, exclude_none=True, exclude={"name"}),
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
                log.warning(f"Tool {internal_tool.name} Blocked by Security Scan")
            except McpRelayScanError:
                log.error(f"Security Scan Failed for tool: {internal_tool.name}")
                internal_tool.state = ToolState.DISABLED_ERROR
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
                return await self._list_tools()
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
                result = await self._call_tool(name, arguments)
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

    @validate_call
    async def _list_tools(self) -> list[types.Tool]:
        """Handle the list_tools request."""
        available_tool_list: list[types.Tool] = []
        if self.tool_registry.is_registry_outdated():
            await self._update_tool_registry()

        # Process each tool
        for tool_name, tool in self.tool_registry.get_available_tools().items():
            log.debug(f"Processing tool: {tool_name}")
            available_tool_list.append(tool.to_mcp_tool())

        log.debug(f"total tools: {len(available_tool_list)}")
        return available_tool_list

    @validate_call
    async def _call_tool(self, name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        """Handle tool execution requests."""
        input_data = {name: arguments}
        input_text = yaml.safe_dump(input_data, sort_keys=False)

        # Scan the request for security issues
        # Raises McpRelaySecurityBlockError if AI Profile blocked content
        await self.scanner.scan(ScanSource.call_tool, ScanType.scan_request, input_text)

        # Get the server for this tool
        available_tools = self.tool_registry.get_available_tools()

        if name not in available_tools:
            err_msg = f"Unknown tool: {name}"
            log.error(err_msg)
            log.debug("Available tools:")
            for tool_name in sorted(available_tools):
                log.debug(tool_name)
            raise McpRelayToolNotFoundError(err_msg)

        # Execute the tool on the downstream server
        result = await self._client_session_group.call_tool(name, arguments)

        result_content = self.extract_text_content(result.content)

        await self.scanner.scan(ScanSource.call_tool, ScanType.scan_response, input_text, str(result_content))

        if result.isError:
            log.error(str(result.content))

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
