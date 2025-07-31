"""
Downstream MCP Client module.

Manages connections and communication with downstream MCP servers.
"""

import asyncio
import logging
import os
from contextlib import AsyncExitStack
from typing import Any, Dict, Optional

import mcp.types as types
from mcp import ClientSession, StdioServerParameters, stdio_client
from tenacity import retry, stop_after_attempt, wait_fixed
from mcp.client.sse import sse_client


class DownstreamMcpClient:
    """
    Manages MCP server connections and tool execution.

    Handles initialization, tool listing, and execution for a single
    downstream MCP server.
    """

    def __init__(self, name: str, config: Dict[str, Any]) -> None:
        """
        Initialize the MCP client.

        Args:
            name: Server identifier
            config: Server configuration dictionary
        """
        self.name: str = name
        self.config: Dict[str, Any] = config
        self.session: Optional[ClientSession] = None
        self._cleanup_lock: asyncio.Lock = asyncio.Lock()
        self.exit_stack: AsyncExitStack = AsyncExitStack()
        logging.info(f"Server {name} created with config: {config}")

    async def initialize(self) -> None:
        """
        Initialize the server connection.

        Sets up communication with the downstream server and creates
        a client session for tool operations.

        Raises:
            Exception: If initialization fails
        """
        logging.debug(f"Initializing downstream mcp server: {self.name}...")

        # Prepare environment variables
        env = os.environ.copy()
        if self.config.get("env"):
            env.update(self.config["env"])

        connection_type = self.config.get("type")
        try:
            if connection_type == "sse":
                # SSE connection
                base_url = self.config.get("baseUrl")
                if not base_url:
                    raise ValueError("SSE connection requires 'baseUrl'")
                
                sse_transport = await self.exit_stack.enter_async_context(
                    sse_client(base_url)
                )
                read, write = sse_transport
            else:
                # Stdio connection (default)
                server_params = StdioServerParameters(
                    command=self.config["command"], args=self.config["args"]
                )
                stdio_transport = await self.exit_stack.enter_async_context(
                    stdio_client(server_params)
                )
                read, write = stdio_transport
            # Create and initialize session
            session = await self.exit_stack.enter_async_context(
                ClientSession(read, write)
            )
            await session.initialize()
            self.session = session

            logging.debug(f"Server {self.name} initialized successfully")
        except Exception as e:
            logging.error(f"Error initializing server {self.name}: {e}", exc_info=True)
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
        arguments: Dict[str, Any],
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
            logging.info(f"Executing {tool_name}...")
            logging.info(f"arguments: {arguments}")
            result = await self.session.call_tool(tool_name, arguments)
            return result
        except Exception as e:
            logging.error(f"Error executing {tool_name}: {e}", exc_info=True)
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
        if isinstance(
            content, (types.EmbeddedResource, types.ImageContent, types.TextContent)
        ):
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
            except Exception as e:
                logging.error(f"Error during cleanup of server {self.name}: {e}")
