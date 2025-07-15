"""
Pan Security Relay Client

A client for the Pan Security Relay MCP server that provides a simple interface
to interact with the security-enhanced MCP relay. This client can connect to
the relay server using either stdio or SSE transport and execute tools through
the security layer.

Features:
- Support for both stdio and SSE transport methods
- Tool discovery and listing
- Tool execution with security scanning
- Error handling and logging
- Interactive mode for testing

Classes:
    PanSecurityRelayClient: Main client class for interacting with the relay server
Functions:
    main: Entry point with command-line interface for testing
"""

import argparse
import asyncio
import json
import logging
import sys
from typing import Any, Dict, List, Optional

from contextlib import AsyncExitStack
import mcp.types as types
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession

logging.basicConfig(
    level=logging.INFO,
    format="[Pan Security Client] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)


class PanSecurityRelayClient:
    def __init__(
        self,
        transport_type: str = "stdio",
        host: str = "127.0.0.1",
        port: int = 8000,
        relay_file_path: Optional[str] = None,
        config_file_path: Optional[str] = None,
    ):
        self.transport_type = transport_type
        self.host = host
        self.port = port
        self.relay_file_path = relay_file_path
        self.config_file_path = config_file_path
        self.session: Optional[ClientSession] = None
        self._cleanup_lock: asyncio.Lock = asyncio.Lock()
        self.exit_stack: AsyncExitStack = AsyncExitStack()
        self.available_tools: List[types.Tool] = []

    async def connect(self) -> None:
        try:
            if self.transport_type == "stdio":
                read, write = await self._initialize_stdio_transport()
            elif self.transport_type == "sse":
                read, write = await self._initialize_sse_transport()
            else:
                raise ValueError(f"Unsupported transport type: {self.transport_type}")

            self.session = await self.exit_stack.enter_async_context(
                ClientSession(read, write)
            )
            if self.session:
                await self.session.initialize()
                logging.info("MCP session initialized successfully")

        except Exception as e:
            await self.cleanup()
            logging.error(f"Failed to connect to Pan Security Relay: {e}")
            raise ConnectionError(f"Connection failed: {e}")

    async def _initialize_stdio_transport(self) -> None:
        from mcp import stdio_client, StdioServerParameters

        if not self.relay_file_path or not self.config_file_path:
            raise ValueError(
                "Both relay_file_path and config_file_path must be provided for stdio transport"
            )

        server_params = StdioServerParameters(
            command="python",
            args=[self.relay_file_path, f"--config-file={self.config_file_path}"],
        )
        logging.info("Creating stdio transport...")
        stdio_transport = await self.exit_stack.enter_async_context(
            stdio_client(server_params)
        )
        return stdio_transport

    async def _initialize_sse_transport(self) -> None:
        url = f"http://{self.host}:{self.port}"
        read_stream, write_stream = await sse_client(url)
        logging.info(f"Connecting to SSE server at {url}")
        stdio_transport = await self.exit_stack.enter_async_context(sse_client(url))
        return stdio_transport

    async def cleanup(self) -> None:
        """Clean up server resources."""
        async with self._cleanup_lock:
            try:
                await self.exit_stack.aclose()
                self.session = None
                self.stdio_context = None
            except Exception as e:
                logging.error(f"Error during cleanup of server {self.name}: {e}")

    async def list_tools(self, refresh: bool = False) -> List[types.Tool]:
        if not self.session:
            raise ConnectionError(
                "Not connected to Pan Security Relay. Call connect() first."
            )

        if refresh or not self.available_tools:
            try:
                response = await self.session.list_tools()
                self.available_tools = response.tools
                logging.info(
                    f"Retrieved {len(self.available_tools)} tools from relay server"
                )
            except Exception as e:
                logging.error(f"Failed to list tools: {e}")
                raise RuntimeError(f"Tool listing failed: {e}")

        return self.available_tools

    async def call_tool(
        self, name: str, arguments: Optional[Dict[str, Any]] = None
    ) -> types.CallToolResult:
        if not self.session:
            raise ConnectionError(
                "Not connected to Pan Security Relay. Call connect() first."
            )

        if arguments is None:
            arguments = {}

        tools = await self.list_tools()
        if not any(tool.name == name for tool in tools):
            available_names = [tool.name for tool in tools]
            raise ValueError(
                f"Tool '{name}' not found. Available tools: {available_names}"
            )

        try:
            logging.info(f"Executing tool '{name}' with arguments: {arguments}")
            result = await self.session.call_tool(name, arguments)

            if result.isError:
                logging.error(f"Tool execution failed: {result.content}")
                raise RuntimeError(f"Tool '{name}' execution failed: {result.content}")

            logging.info(f"Tool '{name}' executed successfully")
            return result

        except Exception as e:
            logging.error(f"Error executing tool '{name}': {e}")
            raise RuntimeError(f"Tool execution error: {e}")

    async def get_tool_info(self, name: str) -> Optional[types.Tool]:
        tools = await self.list_tools()
        return next((tool for tool in tools if tool.name == name), None)

    async def get_server_info(self) -> Dict[str, Any]:
        try:
            result = await self.call_tool("list_downstream_servers_info")
            if result.content and hasattr(result.content[0], "text"):
                return json.loads(result.content[0].text)
            return {}
        except Exception as e:
            logging.error(f"Failed to get server info: {e}")
            raise RuntimeError(f"Server info request failed: {e}")

    def print_tools_summary(self, tools: Optional[List[types.Tool]] = None) -> None:
        if tools is None:
            tools = self.available_tools

        if not tools:
            print("No tools available.")
            return

        print(f"\n=== Available Tools ({len(tools)}) ===")
        for i, tool in enumerate(tools, 1):
            print(f"\n{i}. {tool.name}")
            print(f"   Description: {tool.description}")
            if tool.inputSchema and tool.inputSchema.get("properties"):
                required = tool.inputSchema.get("required", [])
                optional = [
                    prop
                    for prop in tool.inputSchema["properties"]
                    if prop not in required
                ]
                if required:
                    print(f"   Required parameters: {', '.join(required)}")
                if optional:
                    print(f"   Optional parameters: {', '.join(optional)}")


async def interactive_mode(client: PanSecurityRelayClient) -> None:
    print("\n=== Pan Security Relay Client - Interactive Mode ===")
    print("Commands:")
    print("  list - List available tools")
    print("  info <tool_name> - Get tool information")
    print("  call <tool_name> [json_args] - Call a tool")
    print("  servers - Show downstream server info")
    print("  quit - Exit interactive mode")
    print("=" * 50)

    while True:
        try:
            command = input("\n> ").strip()

            if command == "quit":
                break
            elif command == "list":
                tools = await client.list_tools(refresh=True)
                client.print_tools_summary(tools)
            elif command.startswith("info "):
                tool_name = command[5:].strip()
                tool = await client.get_tool_info(tool_name)
                if tool:
                    print(f"\nTool: {tool.name}\nDescription: {tool.description}")
                    print(f"Input Schema: {json.dumps(tool.inputSchema, indent=2)}")
                else:
                    print(f"Tool '{tool_name}' not found")
            elif command.startswith("call "):
                parts = command[5:].strip().split(" ", 1)
                tool_name = parts[0]
                args = {}
                if len(parts) > 1:
                    try:
                        args = json.loads(parts[1])
                    except json.JSONDecodeError:
                        print("Invalid JSON arguments")
                        continue
                try:
                    result = await client.call_tool(tool_name, args)
                    print("\nResult:")
                    for content in result.content:
                        print(getattr(content, "text", str(content)))
                except Exception as e:
                    print(f"Error: {e}")
            elif command == "servers":
                try:
                    server_info = await client.get_server_info()
                    print("\nServer Info:")
                    print(json.dumps(server_info, indent=2))
                except Exception as e:
                    print(f"Error getting server info: {e}")
            else:
                print("Unknown command. Type 'quit' to exit.")

        except (KeyboardInterrupt, EOFError):
            break
        except Exception as e:
            print(f"Error: {e}")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Pan Security Relay Client")
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse"],
        help="Transport protocol",
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1", help="Host for SSE transport"
    )
    parser.add_argument("--port", type=int, default=8000, help="Port for SSE transport")
    parser.add_argument(
        "--relay-file",
        type=str,
        default="pan_aisecurity_mcp/mcp_relay/pan_security_relay.py",
        help="Relay file path for STDIO transport",
    )
    parser.add_argument(
        "--config-file",
        type=str,
        default="config/servers_config_example.json",
        help="Config file path for STDIO transport",
    )
    parser.add_argument("--tool", type=str, help="Tool name to execute")
    parser.add_argument("--args", type=str, help="JSON arguments for tool execution")
    parser.add_argument(
        "--list-tools", action="store_true", help="List available tools and exit"
    )
    parser.add_argument(
        "--example", action="store_true", help="Show execution examples"
    )

    args = parser.parse_args()
    if args.example:
        print("\nExecution Examples:")
        print("1. List available tools:")
        print(
            "   python examples/pan_security_relay_client.py --transport=stdio --relay-file=pan_aisecurity_mcp/mcp_relay/pan_security_relay.py --config-file=config/servers_config.json --list-tools"
        )
        print("\n2. Call a specific tool:")
        print(
            '   python examples/pan_security_relay_client.py --transport=stdio --relay-file=pan_aisecurity_mcp/mcp_relay/pan_security_relay.py --config-file=config/servers_config.json --tool <tool_name> --args \'{"param1": "value1"}\''
        )
        print("\n3. Interactive mode:")
        print(
            "   python examples/pan_security_relay_client.py --transport=stdio --relay-file=pan_aisecurity_mcp/mcp_relay/pan_security_relay.py --config-file=config/servers_config.json"
        )
        return

    client = PanSecurityRelayClient(
        args.transport, args.host, args.port, args.relay_file, args.config_file
    )

    try:
        await client.connect()

        if args.list_tools:
            tools = await client.list_tools()
            client.print_tools_summary(tools)
        elif args.tool:
            tool_args = {}
            if args.args:
                try:
                    tool_args = json.loads(args.args)
                except json.JSONDecodeError:
                    print("Error: Invalid JSON arguments")
                    sys.exit(1)
            try:
                result = await client.call_tool(args.tool, tool_args)
                print("Result:")
                for content in result.content:
                    print(getattr(content, "text", str(content)))
            except Exception as e:
                print(f"Error: {e}")
                sys.exit(1)
        else:
            await interactive_mode(client)

    except Exception as e:
        logging.error(f"Client error: {e}")
        sys.exit(1)
    finally:
        await client.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
