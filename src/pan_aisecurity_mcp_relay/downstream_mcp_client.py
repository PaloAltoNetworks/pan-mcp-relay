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
Downstream MCP Client module.

Manages connections and communication with downstream MCP servers.
"""

import asyncio
import os
import string
from contextlib import AsyncExitStack
from typing import Any

import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.exceptions import McpError
from pydantic import BaseModel, ConfigDict, Field
from tenacity import retry, stop_after_attempt, wait_fixed

from . import utils
from .configuration import HttpMcpServer, SseMcpServer, StdioMcpServer
from .constants import TransportType
from .exceptions import McpRelayBaseError, McpRelayConfigurationError

log = utils.get_logger(__name__)


class DownstreamMcpClient(BaseModel):
    """
    Manages MCP server connections and tool execution.

    Handles initialization, tool listing, and execution for a single
    downstream MCP server.
    """

    name: str
    config: StdioMcpServer | SseMcpServer | HttpMcpServer
    session: ClientSession | None = Field(default=None, init=False)
    cleanup_lock: asyncio.Lock = Field(default_factory=asyncio.Lock, init=False)
    exit_stack: AsyncExitStack = Field(default_factory=AsyncExitStack, init=False)

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def model_post_init(self, context: Any, /) -> None:
        log.info(f"Server {self.name} created")

    async def initialize(self) -> bool:
        """
        Initialize the server connection.

        Sets up communication with the downstream server and creates
        a client session for tool operations.

        Raises:
            AISecMcpRelayInvalidConfigurationError: If the server configuration is invalid
            Exception: If initialization fails
        """
        log.debug(f"Initializing downstream mcp server: {self.name}...")

        try:
            match self.config:
                case StdioMcpServer():
                    client = self.setup_stdio_client()
                case SseMcpServer():
                    client = self.setup_http_client(TransportType.sse)
                case HttpMcpServer():
                    client = self.setup_http_client(TransportType.http)
                    pass
        except Exception as e:
            err_msg = f"Error setting up server {self.name}: {e}"
            log.exception(err_msg)
            raise McpRelayConfigurationError(err_msg) from e

        try:
            # Set up communication with the server
            transport = await self.exit_stack.enter_async_context(client)
            read, write = transport

            # Create and initialize session
            self.session = await self.exit_stack.enter_async_context(ClientSession(read, write))
            await self.session.initialize()
        except McpError as e:
            log.error(f"Failed to initialize Downstream MCP Server: {e}")
            await self.cleanup()
            return False
        except Exception as e:
            log.error(f"Error initializing server {self.name}: {e}")
            await self.cleanup()
            return False
        log.debug(f"Server {self.name} initialized successfully")
        return True

    def setup_http_client(self, client_type: TransportType):
        if client_type == TransportType.http:
            client_constructor = streamablehttp_client
        elif client_type == TransportType.sse:
            client_constructor = sse_client
        else:
            raise McpRelayBaseError(f"Invalid client HTTP type: {client_type}")
        url = self.config.url
        headers = self.config.headers
        if not url:
            err_msg = f"invalid MCP server configuration: {self.name} (missing url)"
            log.error(err_msg)
            raise McpRelayConfigurationError(err_msg)

        # Parse HTTP Header Values using Environment variables
        env = os.environ.copy()
        for k, v in headers.items():
            headers[k] = string.Template(v).safe_substitute(env)

        kwargs = dict(
            url=self.config.url,
            headers=headers,
            timeout=self.config.timeout,
            sse_read_timeout=self.config.sse_read_timeout,
        )
        if client_type == TransportType.http:
            kwargs.update(dict(terminate_on_close=self.config.terminate_on_close))

        client = client_constructor(**kwargs)
        return client

    def setup_stdio_client(self):
        # Prepare environment variables
        env: dict[str, str] = os.environ.copy()
        if self.config.env:
            env.update(self.config["env"])
        command = self.config.command
        if not command:
            err_msg = f"invalid MCP server configuration: {self.name} (missing command)"
            log.error(err_msg)
            raise McpRelayConfigurationError(err_msg)
        config_env = self.config.env or {}
        # merge env + config_env, giving priority to config_env
        for k, v in config_env.items():
            if v is None:
                continue
            v = v.strip()
            if v:
                env[k] = string.Template(v).safe_substitute(os.environ)
        args = self.config.args
        for i, arg in enumerate(args):
            args[i] = string.Template(arg).safe_substitute(env)
        cwd = self.config.cwd
        if cwd:
            cwd = string.Template(str(cwd)).safe_substitute(env)
        log.info(f"Creating stdio client: '{command} {' '.join(args)}'")
        server_params = StdioServerParameters(command=command, args=args, env=env, cwd=cwd)
        client = stdio_client(server_params)
        return client

    async def list_tools(self) -> dict[str, types.Tool]:
        """
        List available tools from the server.

        Returns:
            List of available tools from the downstream server.

        Raises:
            RuntimeError: If the server is not initialized.
        """
        self._check_initialized()

        tool_list: types.ListToolsResult = await self.session.list_tools()
        tools = {}
        for tool in tool_list.tools:
            tools[tool.name] = tool

        return tools

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    async def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> types.CallToolResult:
        """
        Execute a tool with retry mechanism.

        Args:
            tool_name: Name of the tool to execute
            arguments: Tool arguments

        Returns:
            Tool execution result.

        Raises:
            RuntimeError: If server is not initialized
            Exception: If tool execution fails after all retries
        """
        self._check_initialized()

        try:
            log.info(f"Executing {tool_name}...")
            log.info(f"arguments: {arguments}")
            result = await self.session.call_tool(tool_name, arguments)
            return result
        except Exception as e:
            log.error(f"Error executing {tool_name}: {e}", exc_info=True)
            raise e

    def _check_initialized(self) -> None:
        """
        Check if the server is initialized.

        Raises:
            RuntimeError: If the server is not initialized
        """
        if not self.session:
            raise RuntimeError(f"Server {self.name} not initialized")

    async def cleanup(self) -> None:
        """
        Clean up server resources.

        Closes connections and cleans up the session.
        """
        async with self.cleanup_lock:
            try:
                log.debug(f"Cleanup {self.name}")
                await self.exit_stack.aclose()
                self.session = None
            except Exception:
                log.exception(f"Error during cleanup of server {self.name}")
