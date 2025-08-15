import argparse
import asyncio
import json
import logging
import sys
from contextlib import AsyncExitStack
from enum import StrEnum
from typing import Any

import mcp.types as types
from mcp import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

logging.basicConfig(
    level=logging.INFO,
    format="[Pan Security Client] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)


class InteractiveCommand(StrEnum):
    """
    Enumeration of supported interactive commands used in the interactive_mode.

    These commands allow users to explore the available tools, execute specific tools,
    query downstream server information, or exit the interactive client session.

    Attributes:
        LIST: Display all available tools from the server.
        CALL: Execute a specific tool with optional arguments.
        SERVERS: Retrieve downstream server status and configuration.
        QUIT: Exit the interactive session.
    """

    LIST = "list"
    CALL = "call"
    SERVERS = "servers"
    QUIT = "quit"

    def __eq__(self, other: object) -> bool:
        """
        Override equality comparison to allow case-insensitive comparison with strings.

        Args:
            other (object): The object to compare against, typically a string.

        Returns:
            bool: True if the other object is a string equal to the enum value (case-insensitive),
                  or if it is an InteractiveCommand with the same value.
        """
        if isinstance(other, str):
            return self.value.lower() == other.lower()
        return super().__eq__(other)

    def __hash__(self) -> int:
        """
        Override hash function to ensure consistency with case-insensitive equality.

        Returns:
            int: The hash value of the lowercased enum string value.
        """
        return hash(self.value.lower())


class PanSecurityRelayStdioClient:
    """
    Client to interact with the Pan Security Relay server over stdio transport.

    This client handles connection management, tool listing, tool invocation, and
    downstream server information retrieval via the Model Context Protocol (MCP).
    """

    def __init__(self, relay_module: str, config_file_path: str):
        """Initialize the client with relay module path and config file."""
        self.relay_module = relay_module
        self.config_file_path = config_file_path
        self.session: ClientSession | None = None
        self._cleanup_lock = asyncio.Lock()
        self.exit_stack = AsyncExitStack()
        self.available_tools: list[types.Tool] = []

    async def connect(self):
        """Establish connection to the relay subprocess via stdio transport."""
        try:
            read, write = await self.exit_stack.enter_async_context(
                stdio_client(
                    StdioServerParameters(
                        command="python",
                        args=[
                            "-m",
                            self.relay_module,
                            f"--config-file={self.config_file_path}",
                        ],
                    )
                )
            )
            self.session = await self.exit_stack.enter_async_context(ClientSession(read, write))
            await self.session.initialize()
            logging.info("MCP session initialized successfully")
        except Exception as e:
            await self.cleanup()
            logging.error(f"Failed to connect: {e}")
            raise

    async def cleanup(self):
        """Clean up the session and subprocess resources."""
        async with self._cleanup_lock:
            await self.exit_stack.aclose()
            self.session = None

    async def list_tools(self, refresh=False) -> list[types.Tool]:
        """List available tools, with optional refresh from the server."""
        if self.session is None:
            raise RuntimeError("Not connected")
        if refresh or not self.available_tools:
            resp = await self.session.list_tools()
            self.available_tools = resp.tools
        return self.available_tools

    async def call_tool(self, name: str, args: dict[str, Any] | None = None) -> types.CallToolResult:
        """Invoke a tool by name with optional arguments."""
        if self.session is None:
            raise RuntimeError("Not connected")
        if args is None:
            args = {}
        tools = await self.list_tools()
        if not any(t.name == name for t in tools):
            raise ValueError(f"Tool '{name}' not found")
        result = await self.session.call_tool(name, args)
        if result.isError:
            raise RuntimeError(f"Execution failed: {result.content}")
        return result

    async def get_server_info(self) -> dict[str, Any]:
        """Fetch downstream server information via the special tool."""
        result = await self.call_tool("list_downstream_servers_info")
        return json.loads(result.content[0].text) if result.content else {}


async def interactive_mode(client: PanSecurityRelayStdioClient):
    """
    Interactive command-line interface for interacting with the relay server.

    Supports commands: list, call <tool> <args>, servers, quit
    """
    print("\n=== Pan Security Relay Client Interactive Mode ===")
    print(f"Commands: {', '.join([c.value for c in InteractiveCommand])}")
    while True:
        try:
            command = input("> ").strip()
            if not command:
                continue
            elif command == InteractiveCommand.QUIT:
                break
            elif command == InteractiveCommand.LIST:
                tools = await client.list_tools(refresh=True)
                print(f"Found {len(tools)} tools")
                print(json.dumps([tool.__dict__ for tool in tools], indent=2, default=str))
                continue
            elif command[: len(InteractiveCommand.CALL)] == InteractiveCommand.CALL:
                parts = command.split(" ", 2)
                if len(parts) < 2:
                    print("Usage: call <tool> <args as JSON>")
                    continue
                tool = parts[1]
                args = json.loads(parts[2]) if len(parts) > 2 else {}
                result = await client.call_tool(tool, args)
                for content in result.content:
                    print(getattr(content, "text", str(content)))
                continue
            elif command == InteractiveCommand.SERVERS:
                info = await client.get_server_info()
                print(json.dumps(info, indent=2, default=str))
                continue
            else:
                print("Unknown command")
        except Exception as e:
            print(f"Error: {e}")


async def main():
    """Main entry point for the command-line interface."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--relay-module", type=str, required=True)
    parser.add_argument("--config-file", type=str, required=True)
    args = parser.parse_args()

    client = PanSecurityRelayStdioClient(args.relay_module, args.config_file)
    try:
        await client.connect()
        await interactive_mode(client)
    except Exception as e:
        logging.error(f"Client error: {e}")
        sys.exit(1)
    finally:
        await client.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
