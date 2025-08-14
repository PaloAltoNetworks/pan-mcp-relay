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
import logging
import os
from contextlib import AsyncExitStack
from typing import Any, Optional

import mcp.types as types
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.client.session_group import (  # noqa usage TBD
    SseServerParameters,
    StreamableHttpParameters,
    sse_client,
    streamablehttp_client,
)
from mcp.client.sse import create_mcp_http_client
from mcp.client.streamable_http import create_mcp_http_client  # noqa usage TBD
from tenacity import retry, stop_after_attempt, wait_fixed

from pan_aisecurity_mcp_relay.exceptions import AISecMcpRelayException

log = logging.getLogger(__name__)


class DownstreamMcpClient:
    """
    Manages MCP server connections and tool execution.

    Handles initialization, tool listing, and execution for a single
    downstream MCP server.
    """

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        """
        Initialize the MCP client.

        Args:
            name: Server identifier
            config: Server configuration dictionary
        """
        self.name: str = name
        self.config: dict[str, Any] = config
        self.session: Optional[ClientSession] = None
        self._cleanup_lock: asyncio.Lock = asyncio.Lock()
        self.exit_stack: AsyncExitStack = AsyncExitStack()
        log.info(f"Server {name} created with config: {config}")

    async def initialize(self) -> None:
        """
        Initialize the server connection.

        Sets up communication with the downstream server and creates
        a client session for tool operations.

        Raises:
            Exception: If initialization fails
        """
        log.debug(f"Initializing downstream mcp server: {self.name}...")
        # TODO: Add Streamable HTTP Support

        # Prepare environment variables
        env = os.environ.copy()
        if self.config.get("env"):
            env.update(self.config["env"])

        command = self.config.get("command")
        if not command:
            err_msg = f"invalid MCP server configuration: {self.name} (missing command)"
            log.error(err_msg)
            raise AISecMcpRelayException(err_msg)
        args = self.config.get("args")
        config_env = self.config.get("env")
        if config_env:
            if not isinstance(config_env, dict):
                err_msg = f"invalid MCP server configuration: {self.name} (env is not a map)"
                log.error(err_msg)
                raise AISecMcpRelayException(err_msg)
            env = {
                **env,
                **config_env,
            }  # merge env + config_env, giving priority to config_env
        cwd = self.config.get("cwd")

        server_params = StdioServerParameters(command=command, args=args, env=env, cwd=cwd)

        try:
            # Set up communication with the server
            stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
            read, write = stdio_transport

            # Create and initialize session
            session = await self.exit_stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            self.session = session

            log.debug(f"Server {self.name} initialized successfully")
        except Exception as e:
            log.error(f"Error initializing server {self.name}: {e}", exc_info=True)
            await self.cleanup()
            raise

    async def list_tools(self) -> list[types.Tool]:
        """
        List available tools from the server.

        Returns:
            List of available tools from the downstream server.

        Raises:
            RuntimeError: If the server is not initialized.
        """
        self._check_initialized()

        tools_response = await self.session.list_tools()
        tools = []

        for item in tools_response:
            if isinstance(item, tuple) and item[0] == "tools":
                for tool in item[1]:
                    tools.append(
                        types.Tool(
                            name=tool.name,
                            description=tool.description,
                            inputSchema=tool.inputSchema,
                        )
                    )

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
        async with self._cleanup_lock:
            try:
                await self.exit_stack.aclose()
                self.session = None
            except:  # noqa
                log.exception(f"Error during cleanup of server {self.name}")
