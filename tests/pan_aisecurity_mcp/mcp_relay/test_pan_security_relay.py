# Copyright (c) 2025, Palo Alto Networks
#
# Licensed under the Polyform Internal Use License 1.0.0 (the "License");
# you may not use this file except in compliance with the License.

import asyncio
import unittest
from unittest.mock import AsyncMock, patch, Mock

from pan_aisecurity_mcp.mcp_relay.pan_security_relay import PanSecurityRelay
from pan_aisecurity_mcp.mcp_relay.exceptions import AISecMcpRelayException, ErrorType
import mcp.types as types
from pan_aisecurity_mcp.mcp_relay.tool import InternalTool, ToolState
from mcp.server.lowlevel import Server

from pan_aisecurity_mcp.mcp_relay.constants import (
    MAX_DOWNSTREAM_SERVERS_DEFAULT,
    MAX_DOWNSTREAM_TOOLS_DEFAULT,
    TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO,
)


class TestPanSecurityRelay(unittest.IsolatedAsyncioTestCase):
    """Comprehensive test suite for PanSecurityRelay functionality."""
    
    async def asyncSetUp(self):
        """Set up minimal test fixtures."""
        # Basic valid configuration
        self.valid_config = {
            "mcpServers": {
                "pan-aisecurity": {
                    "command": "python",
                    "args": ["aisecurity/mcp_server/pan_security_server.py"],
                    "env": {"hidden_mode": "enabled"}
                },
                "sqlite": {
                    "command": "python",
                    "args": ["/Users/test/sqlite_server.py"]
                }
            }
        }
        
        # Configuration missing pan-aisecurity
        self.config_missing_pan_security = {
            "mcpServers": {
                "sqlite": {
                    "command": "python",
                    "args": ["/Users/test/sqlite_server.py"]
                },
                "weather": {
                    "command": "python",
                    "args": ["/Users/test/weather_server.py"]
                }
            }
        }
        
        # Mock scan results
        self.benign_scan_result = {
            "report_id": "Rfed6481f-b349-44c0-b6cb-72a4219efbc6",
            "scan_id": "fed6481f-b349-44c0-b6cb-72a4219efbc6",
            "profile_id": "f5fc6a93-e739-4afd-a6b6-40b307555efc",
            "profile_name": "stg-wf-dlp",
            "category": "benign",
            "action": "allow"
        }
        
        self.malicious_scan_result = {
            "report_id": "R9b6ff47b-7dc2-4bab-97a7-67962c6c2c3e",
            "scan_id": "9b6ff47b-7dc2-4bab-97a7-67962c6c2c3e",
            "profile_id": "f5fc6a93-e739-4afd-a6b6-40b307555efc",
            "profile_name": "stg-wf-dlp",
            "category": "malicious",
            "action": "block"
        }

    # ===================== Initialization Tests =====================
    
    def test_init_with_parameters(self):
        """Test initialization with various parameters."""
        # Test default parameters
        relay = PanSecurityRelay("/test/config.json")
        self.assertEqual(relay.config_path, "/test/config.json")
        self.assertEqual(relay.max_downstream_servers, MAX_DOWNSTREAM_SERVERS_DEFAULT)
        self.assertEqual(relay.max_downstream_tools, MAX_DOWNSTREAM_TOOLS_DEFAULT)
        
        # Test custom parameters
        relay_custom = PanSecurityRelay(
            "/custom/config.json",
            tool_registry_cache_expiry=600,
            max_downstream_servers=10,
            max_downstream_tools=200
        )
        self.assertEqual(relay_custom.config_path, "/custom/config.json")
        self.assertEqual(relay_custom.max_downstream_servers, 10)
        self.assertEqual(relay_custom.max_downstream_tools, 200)

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._update_tool_registry')
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._update_security_scanner')
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._load_config')
    async def test_initialize_success(self, mock_load_config, mock_update_security_scanner, mock_update_tool_registry):
        """Test successful initialization flow."""
        mock_load_config.return_value = self.valid_config["mcpServers"]
        mock_update_security_scanner.return_value = None
        mock_update_tool_registry.return_value = None
        
        relay = PanSecurityRelay("/test/config.json")
        await relay.initialize()
        
        mock_load_config.assert_called_once()
        mock_update_security_scanner.assert_called_once()
        mock_update_tool_registry.assert_called_once()

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._load_config')
    async def test_initialize_config_missing_pan_security(self, mock_load_config):
        """Test initialization failure when config has valid file but missing pan-aisecurity server."""
        mock_load_config.return_value = self.config_missing_pan_security["mcpServers"]
        
        relay = PanSecurityRelay("/test/config.json")
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await relay.initialize()
        
        self.assertEqual(context.exception.error_type, ErrorType.INVALID_CONFIGURATION)
        self.assertIn("Missing pan-aisecurity mcp server", str(context.exception))

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._load_config')
    async def test_initialize_config_load_failure(self, mock_load_config):
        """Test initialization failure when config loading fails."""
        mock_load_config.side_effect = AISecMcpRelayException(
            "Configuration file not found", ErrorType.INVALID_CONFIGURATION
        )
        
        relay = PanSecurityRelay("/nonexistent/config.json")
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await relay.initialize()
        
        self.assertEqual(context.exception.error_type, ErrorType.INVALID_CONFIGURATION)
        self.assertIn("Configuration file not found", str(context.exception))

    # ===================== Configuration Management Tests =====================
    
    @patch('pan_aisecurity_mcp.mcp_relay.configuration.Configuration.load_config')
    def test_load_config_scenarios(self, mock_load_config):
        """Test various configuration loading scenarios."""
        relay = PanSecurityRelay("/test/config.json")
        
        # Test successful loading
        mock_load_config.return_value = self.valid_config
        result = relay._load_config()
        self.assertEqual(result, self.valid_config["mcpServers"])
        
        # Test file not found
        mock_load_config.side_effect = FileNotFoundError("No such file")
        with self.assertRaises(AISecMcpRelayException) as context:
            relay._load_config()
        self.assertEqual(context.exception.error_type, ErrorType.INVALID_CONFIGURATION)
        
        # Test invalid format
        mock_load_config.side_effect = None
        mock_load_config.return_value = {"mcpServers": "invalid_format"}
        with self.assertRaises(AISecMcpRelayException) as context:
            relay._load_config()
        self.assertIn("Unexpected configuration format", str(context.exception))
        
        # Test no servers
        mock_load_config.return_value = {"mcpServers": {}}
        with self.assertRaises(AISecMcpRelayException) as context:
            relay._load_config()
        self.assertIn("No MCP servers configured", str(context.exception))

    @patch('pan_aisecurity_mcp.mcp_relay.configuration.Configuration.load_config')
    def test_load_config_exceed_max_servers(self, mock_load_config):
        """Test configuration loading when exceeding maximum server limit."""
        # Create config that exceeds limit
        large_config = {"mcpServers": {f"server_{i}": {"command": "test"} for i in range(10)}}
        mock_load_config.return_value = large_config
        
        relay = PanSecurityRelay("/test/config.json", max_downstream_servers=2)
        
        with self.assertRaises(AISecMcpRelayException) as context:
            relay._load_config()
        
        self.assertEqual(context.exception.error_type, ErrorType.INVALID_CONFIGURATION)
        self.assertIn("MCP servers configuration limit exceeded", str(context.exception))

    # ===================== Security Scanner Tests =====================
    
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.DownstreamMcpClient.initialize')
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.DownstreamMcpClient.cleanup')
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner')
    async def test_update_security_scanner_success(self, mock_security_scanner, mock_cleanup, mock_initialize):
        """Test successful security scanner setup."""
        mock_initialize.return_value = None
        mock_cleanup.return_value = None
        mock_security_scanner.return_value = AsyncMock()
        
        relay = PanSecurityRelay("/test/config.json")
        await relay._update_security_scanner(self.valid_config["mcpServers"])
        
        self.assertIsNotNone(relay.security_scanner)
        self.assertIn("pan-aisecurity", relay.servers)

    # ===================== Tool Management Tests =====================
    
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._disable_tools_with_duplicate_names')
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._validate_tool_limits')
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._collect_tools_from_servers')
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._load_config')
    async def test_update_tool_registry_success(self, mock_load_config, mock_collect_tools, 
                                               mock_validate_limits, mock_disable_duplicates):
        """Test successful tool registry update."""
        mock_load_config.return_value = self.valid_config["mcpServers"]
        mock_tools = [InternalTool(
            name="test_tool", description="Test", inputSchema={}, 
            annotations=None, server_name="test", state=ToolState.ENABLED
        )]
        mock_collect_tools.return_value = mock_tools
        
        relay = PanSecurityRelay("/test/config.json")
        relay.tool_registry = Mock()
        
        await relay._update_tool_registry()
        
        mock_collect_tools.assert_called_once()
        mock_validate_limits.assert_called_once()
        mock_disable_duplicates.assert_called_once()
        relay.tool_registry.update_registry.assert_called_once()

    def test_validate_tool_limits_exceeded(self):
        """Test tool limits validation when exceeding maximum tools."""
        max_tools = 3
        tools = [InternalTool(
            name=f"tool_{i}", description="Test", inputSchema={},
            annotations=None, server_name="test", state=ToolState.ENABLED
        ) for i in range(max_tools + 1)]
        
        relay = PanSecurityRelay("/test/config.json", max_downstream_tools=max_tools)
        
        with self.assertRaises(AISecMcpRelayException) as context:
            relay._validate_tool_limits(tools)
        
        self.assertEqual(context.exception.error_type, ErrorType.INVALID_CONFIGURATION)
        self.assertIn(f"maximum allowed: {max_tools}", str(context.exception))

    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.should_block')
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.scan_tool')
    async def test_prepare_tool_with_security_scan(self, mock_scan_tool, mock_should_block):
        """Test tool preparation with different security scan results."""
        relay = PanSecurityRelay("/test/config.json")
        relay.tool_registry = Mock()
        relay.tool_registry.get_tool_by_hash.return_value = None
        relay.security_scanner = Mock()
        relay.security_scanner.scan_tool = mock_scan_tool
        relay.security_scanner.should_block = mock_should_block
        
        test_tool = types.Tool(name="test_tool", description="Test", inputSchema={})
        
        # Test case 1: Benign scan result (tool enabled)
        with self.subTest(case="benign_scan"):
            mock_scan_tool.return_value = self.benign_scan_result
            mock_should_block.return_value = False
            
            tool_list = []
            await relay._prepare_tool("test_server", [test_tool], False, tool_list)
            
            self.assertEqual(len(tool_list), 1)
            self.assertEqual(tool_list[0].state, ToolState.ENABLED)
        
        # Test case 2: Malicious scan result (tool disabled)
        with self.subTest(case="malicious_scan"):
            mock_scan_tool.return_value = self.malicious_scan_result
            mock_should_block.return_value = True
            
            tool_list = []
            await relay._prepare_tool("test_server", [test_tool], False, tool_list)
            
            self.assertEqual(len(tool_list), 1)
            self.assertEqual(tool_list[0].state, ToolState.DISABLED_SECURITY_RISK)
        
        # Test case 3: Hidden mode (tool disabled)
        with self.subTest(case="hidden_mode"):
            tool_list = []
            await relay._prepare_tool("pan-aisecurity", [test_tool], True, tool_list)
            
            self.assertEqual(len(tool_list), 1)
            self.assertEqual(tool_list[0].state, ToolState.DISABLED_HIDDEN_MODE)


    def test_disable_tools_with_duplicate_names(self):
        """Test disabling tools with duplicate names."""
        tools = [
            InternalTool(name="ping", description="Tool 1", inputSchema={}, 
                        annotations=None, server_name="server1", state=ToolState.ENABLED),
            InternalTool(name="ping", description="Tool 2", inputSchema={}, 
                        annotations=None, server_name="server2", state=ToolState.ENABLED),
            InternalTool(name="unique", description="Unique", inputSchema={}, 
                        annotations=None, server_name="server1", state=ToolState.ENABLED)
        ]
        
        relay = PanSecurityRelay("/test/config.json")
        relay._disable_tools_with_duplicate_names(tools)
        
        # Both ping tools should be disabled
        ping_tools = [tool for tool in tools if tool.name == "ping"]
        for ping_tool in ping_tools:
            self.assertEqual(ping_tool.state, ToolState.DISABLED_DUPLICATE)
        
        # Unique tool should remain enabled
        unique_tool = [tool for tool in tools if tool.name == "unique"][0]
        self.assertEqual(unique_tool.state, ToolState.ENABLED)

    # ===================== MCP Server Handling Tests =====================
    
    async def test_launch_mcp_server_success(self):
        """Test successful MCP server creation."""
        relay = PanSecurityRelay("/test/config.json")
        server = await relay.launch_mcp_server()
        
        self.assertIsNotNone(server)
        self.assertIsInstance(server, Server)

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._update_tool_registry')
    async def test_handle_list_tools_scenarios(self, mock_update_tool_registry):
        """Test tool listing scenarios including outdated registry."""
        relay = PanSecurityRelay("/test/config.json")
        relay.tool_registry = Mock()
        
        mock_tools = [InternalTool(
            name="test_tool", description="Test", inputSchema={},
            annotations=None, server_name="test", state=ToolState.ENABLED
        )]
        relay.tool_registry.get_available_tools.return_value = mock_tools
        
        # Test with up-to-date registry
        relay.tool_registry.is_registry_outdated.return_value = False
        result = await relay._handle_list_tools()
        
        self.assertEqual(len(result), 2)  # 1 tool + 1 relay info tool
        tool_names = [tool.name for tool in result]
        self.assertIn("test_tool", tool_names)
        self.assertIn(TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO, tool_names)
        mock_update_tool_registry.assert_not_called()
        
        # Test with outdated registry
        relay.tool_registry.is_registry_outdated.return_value = True
        await relay._handle_list_tools()
        mock_update_tool_registry.assert_called_once()

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._execute_on_server')
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.should_block')
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.scan_response')
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.scan_request')
    async def test_handle_tool_execution_security_blocks(self, mock_scan_request, mock_scan_response,
                                                        mock_should_block, mock_execute_on_server):
        """Test tool execution blocked at different stages."""
        mock_scan_request.return_value = self.benign_scan_result
        mock_scan_response.return_value = self.malicious_scan_result
        mock_execute_on_server.return_value = types.CallToolResult(
            content=[types.TextContent(type="text", text="Success")], isError=False
        )
        
        relay = PanSecurityRelay("/test/config.json")
        relay.tool_registry = Mock()
        relay.tool_registry.get_available_tools.return_value = [InternalTool(
            name="test_tool", description="Test", inputSchema={},
            annotations=None, server_name="test_server", state=ToolState.ENABLED
        )]
        relay.security_scanner = Mock()
        relay.security_scanner.scan_request = mock_scan_request
        relay.security_scanner.scan_response = mock_scan_response
        relay.security_scanner.should_block = mock_should_block
        relay.security_scanner.pan_security_server = Mock()
        relay.security_scanner.pan_security_server.extract_text_content.return_value = "Success"
        
        # Test case 1: Request blocked
        with self.subTest(case="request_blocked"):
            mock_should_block.return_value = True
            
            with self.assertRaises(AISecMcpRelayException) as context:
                await relay._handle_tool_execution("test_tool", {})
            
            self.assertEqual(context.exception.error_type, ErrorType.SECURITY_BLOCK)
            self.assertIn("Unsafe Request", str(context.exception))
        
        # Test case 2: Response blocked
        with self.subTest(case="response_blocked"):
            mock_should_block.side_effect = [False, True]  # Request passes, response blocks
            
            with self.assertRaises(AISecMcpRelayException) as context:
                await relay._handle_tool_execution("test_tool", {})
            
            self.assertEqual(context.exception.error_type, ErrorType.SECURITY_BLOCK)
            self.assertIn("Unsafe Response", str(context.exception))
            
            # Reset side_effect for next test
            mock_should_block.side_effect = None

        # Test case 3: Successful execution (no blocks)
        with self.subTest(case="successful_execution"):
            mock_should_block.return_value = False
            
            result = await relay._handle_tool_execution("test_tool", {})
            
            self.assertIsInstance(result, types.CallToolResult)
            self.assertFalse(result.isError)


    async def test_handle_tool_execution_tool_not_found(self):
        """Test tool execution with non-existent tool."""
        relay = PanSecurityRelay("/test/config.json")
        relay.security_scanner = Mock()
        relay.security_scanner.scan_request = AsyncMock(return_value=self.benign_scan_result)
        relay.security_scanner.should_block.return_value = False
        relay.tool_registry = Mock()
        relay.tool_registry.get_available_tools.return_value = []
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await relay._handle_tool_execution("nonexistent_tool", {})
        
        self.assertEqual(context.exception.error_type, ErrorType.TOOL_NOT_FOUND)

    # ===================== Server Execution Tests =====================
    
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.DownstreamMcpClient.cleanup')
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.DownstreamMcpClient.execute_tool')
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.DownstreamMcpClient.initialize')
    async def test_execute_on_server_scenarios(self, mock_initialize, mock_execute_tool, mock_cleanup):
        """Test server execution scenarios."""
        success_result = types.CallToolResult(
            content=[types.TextContent(type="text", text="Success")], isError=False
        )
        error_result = types.CallToolResult(
            content=[types.TextContent(type="text", text="Error")], isError=True
        )
        
        relay = PanSecurityRelay("/test/config.json")
        mock_server = Mock()
        mock_server.initialize = mock_initialize
        mock_server.execute_tool = mock_execute_tool
        mock_server.cleanup = mock_cleanup
        relay.servers["test_server"] = mock_server
        
        # Test successful execution
        mock_execute_tool.return_value = success_result
        result = await relay._execute_on_server("test_server", "test_tool", {})
        self.assertEqual(result, success_result)
        
        # Test server not found
        with self.assertRaises(AISecMcpRelayException) as context:
            await relay._execute_on_server("nonexistent_server", "test_tool", {})
        self.assertEqual(context.exception.error_type, ErrorType.SERVER_NOT_FOUND)

    # ===================== Exception Handling Tests =====================
    
    def test_exception_handling(self):
        """Test AISecMcpRelayException creation and behavior."""
        # Test exception with error type
        exception = AISecMcpRelayException("Test message", ErrorType.INVALID_CONFIGURATION)
        self.assertEqual(exception.message, "Test message")
        self.assertEqual(exception.error_type, ErrorType.INVALID_CONFIGURATION)
        self.assertIn(ErrorType.INVALID_CONFIGURATION.value, str(exception))
        
        # Test MCP format conversion
        mcp_result = exception.to_mcp_format()
        self.assertIsInstance(mcp_result, types.CallToolResult)
        self.assertTrue(mcp_result.isError)

    async def test_generic_exception_handling(self):
        """Test handling of generic exceptions in initialization."""
        with patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._load_config') as mock_load_config:
            mock_load_config.side_effect = ValueError("Unexpected error")
            
            relay = PanSecurityRelay("/test/config.json")
            
            with self.assertRaises(AISecMcpRelayException) as context:
                await relay.initialize()
            
            self.assertEqual(context.exception.error_type, ErrorType.AISEC_MCP_RELAY_INTERNAL_ERROR)
            self.assertIn("Unexpected initialization error", str(context.exception))

    # ===================== Special Tools Tests =====================
    
    async def test_handle_list_downstream_servers_info(self):
        """Test handling of the special downstream servers info tool."""
        relay = PanSecurityRelay("/test/config.json")
        relay.tool_registry = Mock()
        relay.tool_registry.get_registry_stats.return_value = "Registry stats"
        relay.tool_registry.get_server_tool_map_json.return_value = '{"servers": {}}'
        
        result = await relay._handle_list_downstream_servers_info()
        
        self.assertIsInstance(result, types.CallToolResult)
        self.assertFalse(result.isError)
        self.assertEqual(len(result.content), 1)

    async def asyncTearDown(self):
        """Clean up after each test."""
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()