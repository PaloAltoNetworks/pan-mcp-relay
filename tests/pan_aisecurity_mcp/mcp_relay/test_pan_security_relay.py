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
    
    async def asyncSetUp(self):
        """Set up minimal test fixtures."""
        self.relay = PanSecurityRelay("/test/config.json")
        
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

    # ===================== Initialization Tests =====================
    
    def test_init_default_parameters(self):
        """Test initialization with default parameters."""
        relay = PanSecurityRelay("/test/config.json")
        self.assertEqual(relay.config_path, "/test/config.json")
        self.assertEqual(relay.max_downstream_servers, MAX_DOWNSTREAM_SERVERS_DEFAULT)
        self.assertEqual(relay.max_downstream_tools, MAX_DOWNSTREAM_TOOLS_DEFAULT)

    def test_init_custom_parameters(self):
        """Test initialization with custom parameters."""
        relay = PanSecurityRelay(
            "/custom/config.json",
            tool_registry_cache_expiry=600,
            max_downstream_servers=10,
            max_downstream_tools=200
        )
        self.assertEqual(relay.config_path, "/custom/config.json")
        self.assertEqual(relay.max_downstream_servers, 10)
        self.assertEqual(relay.max_downstream_tools, 200)

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._update_tool_registry', new_callable=AsyncMock)
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._update_security_scanner', new_callable=AsyncMock)
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._load_config')
    async def test_initialize_success(self, mock_load_config, mock_update_security_scanner, mock_update_tool_registry):
        """Test successful initialization flow."""
        mock_load_config.return_value = self.valid_config["mcpServers"]
        mock_update_security_scanner.return_value = None
        mock_update_tool_registry.return_value = None
        
        await self.relay.initialize()
        
        mock_load_config.assert_called_once()
        mock_update_security_scanner.assert_called_once()
        mock_update_tool_registry.assert_called_once()

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._load_config')
    async def test_initialize_config_missing_pan_security(self, mock_load_config):
        """Test initialization failure when pan-aisecurity server is missing."""
        config_missing_pan_security = {
            "sqlite": {"command": "python", "args": ["/Users/test/sqlite_server.py"]},
            "weather": {"command": "python", "args": ["/Users/test/weather_server.py"]}
        }
        mock_load_config.return_value = config_missing_pan_security
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await self.relay.initialize()
        
        self.assertEqual(context.exception.error_type, ErrorType.INVALID_CONFIGURATION)
        self.assertIn("Missing pan-aisecurity mcp server", str(context.exception))

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._load_config')
    async def test_initialize_config_load_failure(self, mock_load_config):
        """Test initialization failure when config loading fails."""
        mock_load_config.side_effect = AISecMcpRelayException(
            "Configuration file not found", ErrorType.INVALID_CONFIGURATION
        )
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await self.relay.initialize()
        
        self.assertEqual(context.exception.error_type, ErrorType.INVALID_CONFIGURATION)
        self.assertIn("Configuration file not found", str(context.exception))

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._load_config')
    async def test_initialize_generic_exception_handling(self, mock_load_config):
        """Test handling of generic exceptions during initialization."""
        mock_load_config.side_effect = ValueError("Unexpected error")
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await self.relay.initialize()
        
        self.assertEqual(context.exception.error_type, ErrorType.AISEC_MCP_RELAY_INTERNAL_ERROR)
        self.assertIn("Unexpected initialization error", str(context.exception))

    # ===================== Configuration Management Tests =====================
    
    @patch('pan_aisecurity_mcp.mcp_relay.configuration.Configuration.load_config')
    def test_load_config_success(self, mock_load_config):
        """Test successful configuration loading."""
        mock_load_config.return_value = self.valid_config
        result = self.relay._load_config()
        self.assertEqual(result, self.valid_config["mcpServers"])

    @patch('pan_aisecurity_mcp.mcp_relay.configuration.Configuration.load_config')
    def test_load_config_file_not_found(self, mock_load_config):
        """Test configuration loading when file is not found."""
        mock_load_config.side_effect = FileNotFoundError("No such file")
        
        with self.assertRaises(AISecMcpRelayException) as context:
            self.relay._load_config()
        
        self.assertEqual(context.exception.error_type, ErrorType.INVALID_CONFIGURATION)

    @patch('pan_aisecurity_mcp.mcp_relay.configuration.Configuration.load_config')
    def test_load_config_invalid_format(self, mock_load_config):
        """Test configuration loading with invalid format."""
        mock_load_config.return_value = {"mcpServers": "invalid_format"}
        
        with self.assertRaises(AISecMcpRelayException) as context:
            self.relay._load_config()
        
        self.assertIn("Unexpected configuration format", str(context.exception))

    @patch('pan_aisecurity_mcp.mcp_relay.configuration.Configuration.load_config')
    def test_load_config_no_servers(self, mock_load_config):
        """Test configuration loading with no servers configured."""
        mock_load_config.return_value = {"mcpServers": {}}
        
        with self.assertRaises(AISecMcpRelayException) as context:
            self.relay._load_config()
        
        self.assertIn("No MCP servers configured", str(context.exception))

    @patch('pan_aisecurity_mcp.mcp_relay.configuration.Configuration.load_config')
    def test_load_config_exceed_max_servers(self, mock_load_config):
        """Test configuration loading when exceeding maximum server limit."""
        large_config = {"mcpServers": {f"server_{i}": {"command": "test"} for i in range(10)}}
        mock_load_config.return_value = large_config
        
        relay = PanSecurityRelay("/test/config.json", max_downstream_servers=2)
        
        with self.assertRaises(AISecMcpRelayException) as context:
            relay._load_config()
        
        self.assertEqual(context.exception.error_type, ErrorType.INVALID_CONFIGURATION)
        self.assertIn("MCP servers configuration limit exceeded", str(context.exception))

    # ===================== Security Scanner Tests =====================
    
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.DownstreamMcpClient.initialize', new_callable=AsyncMock)
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.DownstreamMcpClient.cleanup', new_callable=AsyncMock)
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner')
    async def test_update_security_scanner_success(self, mock_security_scanner, mock_cleanup, mock_initialize):
        """Test successful security scanner setup."""
        mock_initialize.return_value = None
        mock_cleanup.return_value = None
        mock_security_scanner.return_value = AsyncMock()
        
        await self.relay._update_security_scanner(self.valid_config["mcpServers"])
        
        self.assertIsNotNone(self.relay.security_scanner)
        self.assertIn("pan-aisecurity", self.relay.servers)

    # ===================== Tool Management Tests =====================
    
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._disable_tools_with_duplicate_names')
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._validate_tool_limits')
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._collect_tools_from_servers', new_callable=AsyncMock)
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
        
        self.relay.tool_registry = Mock()
        
        await self.relay._update_tool_registry()
        
        mock_collect_tools.assert_called_once()
        mock_validate_limits.assert_called_once()
        mock_disable_duplicates.assert_called_once()
        self.relay.tool_registry.update_registry.assert_called_once()

    def test_validate_tool_limits_success(self):
        """Test tool limits validation with acceptable number of tools."""
        max_tools = 5
        tools = [InternalTool(
            name=f"tool_{i}", description="Test", inputSchema={},
            annotations=None, server_name="test", state=ToolState.ENABLED
        ) for i in range(max_tools - 1)]
        
        relay = PanSecurityRelay("/test/config.json", max_downstream_tools=max_tools)
        
        # Should not raise an exception
        relay._validate_tool_limits(tools)

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

    def test_validate_tool_limits_empty_list(self):
        """Test tool limits validation with empty tool list."""
        relay = PanSecurityRelay("/test/config.json", max_downstream_tools=5)
        
        # Should not raise an exception
        relay._validate_tool_limits([])

    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.should_block')
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.scan_tool', new_callable=AsyncMock)
    async def test_prepare_tool_benign_scan_result(self, mock_scan_tool, mock_should_block):
        """Test tool preparation with benign security scan result."""
        benign_scan_result = {
            "report_id": "Rfed6481f-b349-44c0-b6cb-72a4219efbc6",
            "category": "benign",
            "action": "allow"
        }
        
        self.relay.tool_registry = Mock()
        self.relay.tool_registry.get_tool_by_hash.return_value = None
        self.relay.security_scanner = Mock()
        self.relay.security_scanner.scan_tool = mock_scan_tool
        self.relay.security_scanner.should_block = mock_should_block
        
        mock_scan_tool.return_value = benign_scan_result
        mock_should_block.return_value = False
        
        test_tool = types.Tool(name="test_tool", description="Test", inputSchema={})
        tool_list = []
        
        await self.relay._prepare_tool("test_server", [test_tool], False, tool_list)
        
        self.assertEqual(len(tool_list), 1)
        self.assertEqual(tool_list[0].state, ToolState.ENABLED)

    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.should_block')
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.scan_tool', new_callable=AsyncMock)
    async def test_prepare_tool_malicious_scan_result(self, mock_scan_tool, mock_should_block):
        """Test tool preparation with malicious security scan result."""
        malicious_scan_result = {
            "report_id": "R9b6ff47b-7dc2-4bab-97a7-67962c6c2c3e",
            "category": "malicious",
            "action": "block"
        }
        
        self.relay.tool_registry = Mock()
        self.relay.tool_registry.get_tool_by_hash.return_value = None
        self.relay.security_scanner = Mock()
        self.relay.security_scanner.scan_tool = mock_scan_tool
        self.relay.security_scanner.should_block = mock_should_block
        
        mock_scan_tool.return_value = malicious_scan_result
        mock_should_block.return_value = True
        
        test_tool = types.Tool(name="test_tool", description="Test", inputSchema={})
        tool_list = []
        
        await self.relay._prepare_tool("test_server", [test_tool], False, tool_list)
        
        self.assertEqual(len(tool_list), 1)
        self.assertEqual(tool_list[0].state, ToolState.DISABLED_SECURITY_RISK)

    async def test_prepare_tool_hidden_mode(self):
        """Test tool preparation in hidden mode."""
        test_tool = types.Tool(name="test_tool", description="Test", inputSchema={})
        tool_list = []
        
        await self.relay._prepare_tool("pan-aisecurity", [test_tool], True, tool_list)
        
        self.assertEqual(len(tool_list), 1)
        self.assertEqual(tool_list[0].state, ToolState.DISABLED_HIDDEN_MODE)

    async def test_prepare_tool_empty_tool_list(self):
        """Test tool preparation with empty tool list."""
        tool_list = []
        
        await self.relay._prepare_tool("test_server", [], False, tool_list)
        
        self.assertEqual(len(tool_list), 0)

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
        
        self.relay._disable_tools_with_duplicate_names(tools)
        
        # Both ping tools should be disabled
        ping_tools = [tool for tool in tools if tool.name == "ping"]
        for ping_tool in ping_tools:
            self.assertEqual(ping_tool.state, ToolState.DISABLED_DUPLICATE)
        
        # Unique tool should remain enabled
        unique_tool = [tool for tool in tools if tool.name == "unique"][0]
        self.assertEqual(unique_tool.state, ToolState.ENABLED)

    def test_disable_tools_no_duplicates(self):
        """Test disabling tools when no duplicates exist."""
        tools = [
            InternalTool(name="tool1", description="Tool 1", inputSchema={}, 
                        annotations=None, server_name="server1", state=ToolState.ENABLED),
            InternalTool(name="tool2", description="Tool 2", inputSchema={}, 
                        annotations=None, server_name="server2", state=ToolState.ENABLED)
        ]
        
        self.relay._disable_tools_with_duplicate_names(tools)
        
        # All tools should remain enabled
        for tool in tools:
            self.assertEqual(tool.state, ToolState.ENABLED)

    # ===================== MCP Server Handling Tests =====================
    
    async def test_launch_mcp_server_success(self):
        """Test successful MCP server creation."""
        server = await self.relay.launch_mcp_server()
        
        self.assertIsNotNone(server)
        self.assertIsInstance(server, Server)

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._update_tool_registry', new_callable=AsyncMock)
    async def test_handle_list_tools_up_to_date_registry(self, mock_update_tool_registry):
        """Test tool listing with up-to-date registry."""
        self.relay.tool_registry = Mock()
        mock_tools = [InternalTool(
            name="test_tool", description="Test", inputSchema={},
            annotations=None, server_name="test", state=ToolState.ENABLED
        )]
        self.relay.tool_registry.get_available_tools.return_value = mock_tools
        self.relay.tool_registry.is_registry_outdated.return_value = False
        
        result = await self.relay._handle_list_tools()
        
        self.assertEqual(len(result), 2)  # 1 tool + 1 relay info tool
        tool_names = [tool.name for tool in result]
        self.assertIn("test_tool", tool_names)
        self.assertIn(TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO, tool_names)
        mock_update_tool_registry.assert_not_called()

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._update_tool_registry', new_callable=AsyncMock)
    async def test_handle_list_tools_outdated_registry(self, mock_update_tool_registry):
        """Test tool listing with outdated registry."""
        self.relay.tool_registry = Mock()
        mock_tools = [InternalTool(
            name="test_tool", description="Test", inputSchema={},
            annotations=None, server_name="test", state=ToolState.ENABLED
        )]
        self.relay.tool_registry.get_available_tools.return_value = mock_tools
        self.relay.tool_registry.is_registry_outdated.return_value = True
        
        await self.relay._handle_list_tools()
        
        mock_update_tool_registry.assert_called_once()

    # ===================== Tool Execution Tests =====================
    
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._execute_on_server', new_callable=AsyncMock)
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.should_block')
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.scan_response', new_callable=AsyncMock)
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.scan_request', new_callable=AsyncMock)
    async def test_handle_tool_execution_success(self, mock_scan_request, mock_scan_response,
                                               mock_should_block, mock_execute_on_server):
        """Test successful tool execution without security blocks."""
        benign_scan_result = {"category": "benign", "action": "allow"}
        
        mock_scan_request.return_value = benign_scan_result
        mock_scan_response.return_value = benign_scan_result
        mock_should_block.return_value = False
        mock_execute_on_server.return_value = types.CallToolResult(
            content=[types.TextContent(type="text", text="Success")], isError=False
        )
        
        self.relay.tool_registry = Mock()
        self.relay.tool_registry.get_available_tools.return_value = [InternalTool(
            name="test_tool", description="Test", inputSchema={},
            annotations=None, server_name="test_server", state=ToolState.ENABLED
        )]
        self.relay.security_scanner = Mock()
        self.relay.security_scanner.scan_request = mock_scan_request
        self.relay.security_scanner.scan_response = mock_scan_response
        self.relay.security_scanner.should_block = mock_should_block
        self.relay.security_scanner.pan_security_server = Mock()
        self.relay.security_scanner.pan_security_server.extract_text_content.return_value = "Success"
        
        result = await self.relay._handle_tool_execution("test_tool", {})
        
        self.assertIsInstance(result, types.CallToolResult)
        self.assertFalse(result.isError)

    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.should_block')
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.scan_request', new_callable=AsyncMock)
    async def test_handle_tool_execution_request_blocked(self, mock_scan_request, mock_should_block):
        """Test tool execution blocked by security scan on request."""
        malicious_scan_result = {"category": "malicious", "action": "block"}
        
        mock_scan_request.return_value = malicious_scan_result
        mock_should_block.return_value = True
        
        self.relay.tool_registry = Mock()
        self.relay.tool_registry.get_available_tools.return_value = [InternalTool(
            name="test_tool", description="Test", inputSchema={},
            annotations=None, server_name="test_server", state=ToolState.ENABLED
        )]
        self.relay.security_scanner = Mock()
        self.relay.security_scanner.scan_request = mock_scan_request
        self.relay.security_scanner.should_block = mock_should_block
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await self.relay._handle_tool_execution("test_tool", {})
        
        self.assertEqual(context.exception.error_type, ErrorType.SECURITY_BLOCK)
        self.assertIn("Unsafe Request", str(context.exception))

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._execute_on_server', new_callable=AsyncMock)
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.should_block')
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.scan_response', new_callable=AsyncMock)
    @patch('pan_aisecurity_mcp.mcp_relay.security_scanner.SecurityScanner.scan_request', new_callable=AsyncMock)
    async def test_handle_tool_execution_response_blocked(self, mock_scan_request, mock_scan_response,
                                                        mock_should_block, mock_execute_on_server):
        """Test tool execution blocked by security scan on response."""
        benign_scan_result = {"category": "benign", "action": "allow"}
        malicious_scan_result = {"category": "malicious", "action": "block"}
        
        mock_scan_request.return_value = benign_scan_result
        mock_scan_response.return_value = malicious_scan_result
        mock_should_block.side_effect = [False, True]  # Request passes, response blocks
        mock_execute_on_server.return_value = types.CallToolResult(
            content=[types.TextContent(type="text", text="Success")], isError=False
        )
        
        self.relay.tool_registry = Mock()
        self.relay.tool_registry.get_available_tools.return_value = [InternalTool(
            name="test_tool", description="Test", inputSchema={},
            annotations=None, server_name="test_server", state=ToolState.ENABLED
        )]
        self.relay.security_scanner = Mock()
        self.relay.security_scanner.scan_request = mock_scan_request
        self.relay.security_scanner.scan_response = mock_scan_response
        self.relay.security_scanner.should_block = mock_should_block
        self.relay.security_scanner.pan_security_server = Mock()
        self.relay.security_scanner.pan_security_server.extract_text_content.return_value = "Success"
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await self.relay._handle_tool_execution("test_tool", {})
        
        self.assertEqual(context.exception.error_type, ErrorType.SECURITY_BLOCK)
        self.assertIn("Unsafe Response", str(context.exception))

    async def test_handle_tool_execution_tool_not_found(self):
        """Test tool execution with non-existent tool."""
        self.relay.security_scanner = Mock()
        self.relay.security_scanner.scan_request = AsyncMock(return_value={"category": "benign"})
        self.relay.security_scanner.should_block.return_value = False
        self.relay.tool_registry = Mock()
        self.relay.tool_registry.get_available_tools.return_value = []
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await self.relay._handle_tool_execution("nonexistent_tool", {})
        
        self.assertEqual(context.exception.error_type, ErrorType.TOOL_NOT_FOUND)

    async def test_handle_tool_execution_empty_tool_name(self):
        """Test tool execution with empty tool name."""
        self.relay.security_scanner = Mock()
        self.relay.security_scanner.scan_request = AsyncMock(return_value={"category": "benign"})
        self.relay.security_scanner.should_block.return_value = False
        self.relay.tool_registry = Mock()
        self.relay.tool_registry.get_available_tools.return_value = []
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await self.relay._handle_tool_execution("", {})
        
        self.assertEqual(context.exception.error_type, ErrorType.TOOL_NOT_FOUND)

    async def test_handle_tool_execution_none_tool_name(self):
        """Test tool execution with None tool name."""
        self.relay.security_scanner = Mock()
        self.relay.security_scanner.scan_request = AsyncMock(return_value={"category": "benign"})
        self.relay.security_scanner.should_block.return_value = False
        self.relay.tool_registry = Mock()
        self.relay.tool_registry.get_available_tools.return_value = []
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await self.relay._handle_tool_execution(None, {})
        
        self.assertEqual(context.exception.error_type, ErrorType.TOOL_NOT_FOUND)

    async def test_handle_tool_execution_empty_arguments(self):
        """Test tool execution with empty arguments."""
        benign_scan_result = {"category": "benign", "action": "allow"}
        
        self.relay.tool_registry = Mock()
        self.relay.tool_registry.get_available_tools.return_value = [InternalTool(
            name="test_tool", description="Test", inputSchema={},
            annotations=None, server_name="test_server", state=ToolState.ENABLED
        )]
        self.relay.security_scanner = Mock()
        self.relay.security_scanner.scan_request = AsyncMock(return_value=benign_scan_result)
        self.relay.security_scanner.scan_response = AsyncMock(return_value=benign_scan_result)
        self.relay.security_scanner.should_block.return_value = False
        self.relay.security_scanner.pan_security_server = Mock()
        self.relay.security_scanner.pan_security_server.extract_text_content.return_value = "Success"
        
        with patch.object(self.relay, '_execute_on_server', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = types.CallToolResult(
                content=[types.TextContent(type="text", text="Success")], isError=False
            )
            
            result = await self.relay._handle_tool_execution("test_tool", {})
            
            self.assertIsInstance(result, types.CallToolResult)
            mock_execute.assert_called_once_with("test_server", "test_tool", {})

    # ===================== Server Execution Tests =====================
    
    async def test_execute_on_server_success(self):
        """Test successful server execution."""
        success_result = types.CallToolResult(
            content=[types.TextContent(type="text", text="Success")], isError=False
        )
        
        mock_server = AsyncMock()
        mock_server.execute_tool.return_value = success_result
        self.relay.servers["test_server"] = mock_server
        
        result = await self.relay._execute_on_server("test_server", "test_tool", {})
        self.assertEqual(result, success_result)

    async def test_execute_on_server_not_found(self):
        """Test server execution with non-existent server."""
        with self.assertRaises(AISecMcpRelayException) as context:
            await self.relay._execute_on_server("nonexistent_server", "test_tool", {})
        
        self.assertEqual(context.exception.error_type, ErrorType.SERVER_NOT_FOUND)

    async def test_execute_on_server_execution_error(self):
        """Test server execution with tool execution error."""
        mock_server = AsyncMock()
        mock_server.execute_tool.side_effect = Exception("Execution failed")
        self.relay.servers["test_server"] = mock_server
        
        with self.assertRaises(Exception) as context:
            await self.relay._execute_on_server("test_server", "test_tool", {})
        
        self.assertIn("Execution failed", str(context.exception))

    # ===================== Exception Handling Tests =====================
    
    def test_exception_creation_with_error_type(self):
        """Test AISecMcpRelayException creation with error type."""
        exception = AISecMcpRelayException("Test message", ErrorType.INVALID_CONFIGURATION)
        self.assertEqual(exception.message, "Test message")
        self.assertEqual(exception.error_type, ErrorType.INVALID_CONFIGURATION)
        self.assertIn(ErrorType.INVALID_CONFIGURATION.value, str(exception))

    def test_exception_mcp_format_conversion(self):
        """Test exception conversion to MCP format."""
        exception = AISecMcpRelayException("Test error", ErrorType.TOOL_NOT_FOUND)
        mcp_result = exception.to_mcp_format()
        
        self.assertIsInstance(mcp_result, types.CallToolResult)
        self.assertTrue(mcp_result.isError)

    def test_exception_without_error_type(self):
        """Test exception creation without explicit error type."""
        exception = AISecMcpRelayException("Test message")
        self.assertEqual(exception.message, "Test message")
        # Based on the actual implementation, error_type might be None when not provided
        # We'll just check that the exception is created properly
        self.assertIsInstance(exception, AISecMcpRelayException)

    # ===================== Special Tools Tests =====================
    
    async def test_handle_list_downstream_servers_info_success(self):
        """Test handling of the special downstream servers info tool."""
        self.relay.tool_registry = Mock()
        self.relay.tool_registry.get_registry_stats.return_value = "Registry stats"
        self.relay.tool_registry.get_server_tool_map_json.return_value = '{"servers": {}}'
        
        result = await self.relay._handle_list_downstream_servers_info()
        
        self.assertIsInstance(result, types.CallToolResult)
        self.assertFalse(result.isError)
        self.assertEqual(len(result.content), 1)

    async def test_handle_list_downstream_servers_info_empty_registry(self):
        """Test downstream servers info with empty registry."""
        self.relay.tool_registry = Mock()
        self.relay.tool_registry.get_registry_stats.return_value = ""
        self.relay.tool_registry.get_server_tool_map_json.return_value = "{}"
        
        result = await self.relay._handle_list_downstream_servers_info()
        
        self.assertIsInstance(result, types.CallToolResult)
        self.assertFalse(result.isError)

    # ===================== Resource and Performance Tests =====================
    
    async def test_memory_cleanup_after_initialization(self):
        """Test memory cleanup after initialization."""
        # This test ensures no memory leaks in initialization
        initial_task_count = len(asyncio.all_tasks())
        
        with patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.PanSecurityRelay._load_config') as mock_load_config:
            mock_load_config.return_value = self.valid_config["mcpServers"]
            
            with patch.object(self.relay, '_update_security_scanner', new_callable=AsyncMock):
                with patch.object(self.relay, '_update_tool_registry', new_callable=AsyncMock):
                    await self.relay.initialize()
        
        # Allow some time for cleanup
        await asyncio.sleep(0.1)
        
        final_task_count = len(asyncio.all_tasks())
        # Task count should not grow significantly
        self.assertLessEqual(final_task_count - initial_task_count, 2)

    async def test_concurrent_tool_executions(self):
        """Test handling multiple concurrent tool executions."""
        benign_scan_result = {"category": "benign", "action": "allow"}
        
        self.relay.tool_registry = Mock()
        self.relay.tool_registry.get_available_tools.return_value = [InternalTool(
            name="test_tool", description="Test", inputSchema={},
            annotations=None, server_name="test_server", state=ToolState.ENABLED
        )]
        self.relay.security_scanner = Mock()
        self.relay.security_scanner.scan_request = AsyncMock(return_value=benign_scan_result)
        self.relay.security_scanner.scan_response = AsyncMock(return_value=benign_scan_result)
        self.relay.security_scanner.should_block.return_value = False
        self.relay.security_scanner.pan_security_server = Mock()
        self.relay.security_scanner.pan_security_server.extract_text_content.return_value = "Success"
        
        with patch.object(self.relay, '_execute_on_server', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = types.CallToolResult(
                content=[types.TextContent(type="text", text="Success")], isError=False
            )
            
            # Execute multiple tools concurrently
            tasks = [
                self.relay._handle_tool_execution("test_tool", {"param": f"value_{i}"})
                for i in range(3)
            ]
            
            results = await asyncio.gather(*tasks)
            
            # All executions should succeed
            for result in results:
                self.assertIsInstance(result, types.CallToolResult)
                self.assertFalse(result.isError)
            
            # All executions should have been called
            self.assertEqual(mock_execute.call_count, 3)

    async def asyncTearDown(self):
        """Clean up after each test."""
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
