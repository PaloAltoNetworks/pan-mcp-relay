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

import logging
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

import mcp.types as types
import uvicorn
from mcp.server.lowlevel import Server
from mcp.server.sse import SseServerTransport
from mcp.server.stdio import stdio_server
from starlette.applications import Starlette
from starlette.routing import Route

from .configuration import Configuration
from .constants import (
    ENVIRONMENT_CONFIG_LABEL,
    HIDDEN_MODE_ENABLED,
    HIDDEN_MODE_LABEL,
    MAX_DOWNSTREAM_SERVERS_DEFAULT,
    MAX_DOWNSTREAM_TOOLS_DEFAULT,
    MCP_RELAY_NAME,
    MCP_SERVER_CONFIG_LABEL,
    TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO,
    TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT,
)
from .downstream_mcp_client import DownstreamMcpClient
from .exceptions import (
    AISecMcpRelayException,
    AISecMcpRelayInternalError,
    AISecMcpRelayInvalidConfigurationError,
    AISecMcpRelaySecurityBlockError,
    AISecMcpRelayServerNotFoundError,
    AISecMcpRelayToolExecutionError,
    AISecMcpRelayToolNotFoundError,
)
from .security_scanner import SecurityScanner
from .tool import InternalTool, ToolState
from .tool_registry import ToolRegistry

__path__ = Path(__file__)

log = logging.getLogger(__path__.stem)


class PanSecurityRelay:
    """Main relay server class that orchestrates tool execution and security scanning."""

    def __init__(
        self,
        config_path: str,
        security_scanner_config: dict[str, Any],
        tool_registry_cache_expiry: int = TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT,
        max_downstream_servers: int = MAX_DOWNSTREAM_SERVERS_DEFAULT,
        max_downstream_tools: int = MAX_DOWNSTREAM_TOOLS_DEFAULT,
    ) -> None:
        """
        Initialize the PanSecurityRelay.

        Args:
            config_path: Path to the configuration file
            security_scanner_config: Configuration dictionary for the security scanner
            tool_registry_cache_expiry: Cache expiry time in seconds
            max_downstream_servers: Maximum number of downstream servers
            max_downstream_tools: Maximum number of tools
        """
        self.servers: dict[str, DownstreamMcpClient] = {}  # Maps server_name to server
        self.tool_registry = ToolRegistry(tool_registry_cache_expiry)
        self.config_path = config_path
        self.security_scanner_config = security_scanner_config
        self.max_downstream_servers = max_downstream_servers
        self.max_downstream_tools = max_downstream_tools
        self.security_scanner: Optional[SecurityScanner] = None

    async def initialize(self) -> None:
        """Initialize the relay server and register all tools."""
        logging.info("Initializing pan security relay...")
        try:
            # Load configuration and validate server configurations
            self._load_config()

            # Store the pan_security server for security scanning
            await self._update_security_scanner(self.security_scanner_config)

            # Configure downstream MCP servers from configuration
            await self._update_tool_registry()

            logging.info("MCP relay server initialized successfully.")
        except AISecMcpRelayException as relay_error:
            logging.error(f"MCP Relay initialization error: {relay_error}")
            raise relay_error
        except Exception as other_error:
            log.exception(f"Failed to initialize MCP relay server, error: {other_error}")
            raise

    def _load_config(self) -> dict[str, Any]:
        """Load and validate configuration file."""
        try:
            config = Configuration().load_config(self.config_path)
            # Validate core configuration sections
            servers_config = config[MCP_SERVER_CONFIG_LABEL]
            if isinstance(servers_config, dict):
                if servers_config is None or len(servers_config.items()) == 0:
                    raise AISecMcpRelayInvalidConfigurationError("No MCP servers configured.")
                if len(servers_config.items()) >= self.max_downstream_servers:
                    raise AISecMcpRelayInvalidConfigurationError(
                        f"MCP servers configuration limit exceeded, maximum allowed: {self.max_downstream_servers}"
                    )
                return servers_config
            else:
                raise AISecMcpRelayInvalidConfigurationError("Unexpected configuration format for servers.")
        except AISecMcpRelayException as validate_error:
            logging.error(f"Configuration validation error: {validate_error}")
            raise validate_error
        except Exception as e:
            logging.error(f"Configuration loading error: {e}")
            raise AISecMcpRelayInvalidConfigurationError(f"Could not load configuration: {e}")

    async def _update_security_scanner(self, security_scanner_config) -> None:
        """Initialize and configure the security scanner for downstream servers."""
        logging.info("MCP pan-aisecurity server init - Setting up security scanning configuration...")

        mcp_server_path = __path__.parent / "mcp_server/pan_security_server.py"
        server = DownstreamMcpClient(
            "pan-aisecurity",
            {
                "command": sys.executable,
                "args": [str(mcp_server_path)],
                "env": security_scanner_config,
            },
        )
        await server.initialize()
        self.servers["pan-aisecurity"] = server
        self.security_scanner = SecurityScanner(server)
        await server.cleanup()

        if self.security_scanner is None:
            raise AISecMcpRelayInvalidConfigurationError("Missing pan-aisecurity mcp server in configuration.")
        logging.info("MCP pan-aisecurity server configured successfully.")

    async def _update_tool_registry(self) -> None:
        """Update the tool registry with tools from all configured servers."""
        logging.info("Updating tool registry...")
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
            await server.initialize()
            self.servers[server_name] = server

            # Register all tools from this server
            server_tools = await server.list_tools()
            hidden_mode_enabled = (
                server_config.get(ENVIRONMENT_CONFIG_LABEL) is not None
                and server_config.get(ENVIRONMENT_CONFIG_LABEL).get(HIDDEN_MODE_LABEL) == HIDDEN_MODE_ENABLED
            )
            await self._prepare_tool(server_name, server_tools, hidden_mode_enabled, full_tool_list)
            await server.cleanup()
        return full_tool_list

    def _validate_tool_limits(self, tools: list[InternalTool]) -> None:
        """Additional validation of tool limits and constraints."""
        if len(tools) > self.max_downstream_tools:
            raise AISecMcpRelayInvalidConfigurationError(
                f"Tools limit exceeded, maximum allowed: {self.max_downstream_tools}"
            )

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
                    logging.info(f"Scan tool info: {server_tool.model_dump()!s}")
                    if self.security_scanner.should_block(await self.security_scanner.scan_tool(server_tool)):
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
                    logging.info(f"Tool '{tool.name}' already in dict, skipping or updating...")
                    name_to_tool_dict[tool.name].state = ToolState.DISABLED_DUPLICATE
                    tool.state = ToolState.DISABLED_DUPLICATE
                else:
                    name_to_tool_dict[tool.name] = tool
        duplicate_tool_names = [
            f"{tool.server_name}:{tool.name}" for tool in tools if tool.state == ToolState.DISABLED_DUPLICATE
        ]
        if len(duplicate_tool_names) > 0:
            logging.warning(f"Duplicate tool names: {duplicate_tool_names}")

    async def launch_mcp_server(self) -> Server:
        """Create and configure the MCP server with handlers."""
        app = Server(MCP_RELAY_NAME)

        @app.list_tools()
        async def list_tools() -> list[types.Tool]:
            logging.info(f"-------------- {MCP_RELAY_NAME}: list_tools --------------")
            try:
                return await self._handle_list_tools()
            except AISecMcpRelayException as relay_error:
                logging.error(f"MCP Relay list tool error: {relay_error}")
                raise relay_error
            except Exception as e:
                logging.error(f"Error listing tools: {e}")
                raise AISecMcpRelayInternalError(f"Failed to list tools: {e}")

        @app.call_tool()
        async def call_tool(
            name: str, arguments: dict
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            logging.info(f"-------------- {MCP_RELAY_NAME}: {name} --------------")
            try:
                result = await self._handle_tool_execution(name, arguments)
                if result.isError:
                    raise AISecMcpRelayToolExecutionError(str(result.content))
                return result.content
            except AISecMcpRelayException as relay_error:
                logging.error(f"MCP Relay call tool error: {relay_error}")
                raise relay_error
            except Exception as e:
                logging.error(f"Error call tool {name}: {e}")
                raise AISecMcpRelayInternalError(f"Failed to call tool {name}: {e}")

        return app

    async def _handle_list_tools(self) -> list[types.Tool]:
        """Handle the list_tools request."""
        available_tool_list: list[types.Tool] = []
        if self.tool_registry.is_registry_outdated():
            await self._update_tool_registry()

        # Process each tool
        for tool in self.tool_registry.get_available_tools():
            logging.debug(f"Processing tool: {tool.name}")
            available_tool_list.append(tool.to_mcp_tool())
            logging.debug(f"Tool {tool.name}: State={tool.state}, Total tools={len(available_tool_list)}")

        # Add the relay info tool
        available_tool_list.append(
            types.Tool(
                name=TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO,
                description="This tool is intended for debugging purposes and provides detailed information about configured downstream servers.",
                inputSchema={"type": "object", "properties": {}},
            )
        )

        return available_tool_list

    async def _handle_tool_execution(self, name: str, arguments: dict) -> types.CallToolResult:
        """Handle tool execution requests."""
        input_text = f"{name}: {arguments!s}"

        # Scan the request for security issues
        if self.security_scanner:
            if self.security_scanner.should_block(await self.security_scanner.scan_request(input_text)):
                raise AISecMcpRelaySecurityBlockError("Unsafe Request: Security scan blocked this request")

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
            raise AISecMcpRelayToolNotFoundError(f"Unknown tool: {name}")

        # Execute the tool on the downstream server
        result = await self._execute_on_server(target_tool.server_name, name, arguments)

        result_content = self.security_scanner.pan_security_server.extract_text_content(result.content)

        if self.security_scanner:
            logging.info(f"scanning: {result_content}")
            if self.security_scanner.should_block(
                await self.security_scanner.scan_response(input_text, str(result_content))
            ):
                raise AISecMcpRelaySecurityBlockError("Unsafe Response: Security scan blocked this response")

        if result.isError:
            raise AISecMcpRelayToolExecutionError(str(result.content))

        return result

    async def _handle_list_downstream_servers_info(self) -> types.CallToolResult:
        logging.info(f"Current tool registry status: {self.tool_registry.get_registry_stats()}")
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=self.tool_registry.get_server_tool_map_json())],
            isError=False,
        )

    async def _execute_on_server(self, server_name: str, tool_name: str, arguments: dict) -> types.CallToolResult:
        """Execute a tool on a specific downstream server."""
        if server_name not in self.servers:
            raise AISecMcpRelayServerNotFoundError(f"Server not found: {server_name}")

        server = self.servers[server_name]
        await server.initialize()

        try:
            logging.info(f"Executing: {server_name} - {tool_name} - {arguments}")
            result = await server.execute_tool(tool_name, arguments)
            return result
        finally:
            await server.cleanup()

    async def run_stdio_server(self, app: Server) -> None:
        """Run the server with stdio transport."""
        logging.info("Starting server with stdio transport.")

        async def arun():
            async with stdio_server() as streams:
                await app.run(streams[0], streams[1], app.create_initialization_options())

        await arun()

    async def run_sse_server(self, app: Server, host: str, port: int) -> None:
        """Run the server with SSE transport."""
        logging.info(f"Starting server with SSE transport on {host}:{port}")

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


def safe_str_to_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default
