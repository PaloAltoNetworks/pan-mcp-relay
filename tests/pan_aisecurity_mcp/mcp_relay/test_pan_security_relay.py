# Copyright (c) 2025, Palo Alto Networks
#
# Licensed under the Polyform Internal Use License 1.0.0 (the "License");
# you may not use this file except in compliance with the License.

import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch
import json
import tempfile
import os

from pan_aisecurity_mcp.mcp_relay.pan_security_relay import PanSecurityRelay
from pan_aisecurity_mcp.mcp_relay.exceptions import AISecMcpRelayException, ErrorType
from pan_aisecurity_mcp.mcp_relay.constants import SECURITY_SERVER_NAME


class TestPanSecurityRelay(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.test_config = {
            "mcpServers": {
                "pan-aisecurity": {
                    "command": "python",
                    "args": ["aisecurity/mcp_server/pan_security_server.py"],
                    "env": {
                        "hidden_mode": "enabled"
                    }
                },
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
        
        # Create temporary config file
        self.temp_config_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(self.test_config, self.temp_config_file)
        self.temp_config_file.close()
        
        # Mock security scan results
        self.mock_benign_scan_result = Mock()
        self.mock_benign_scan_result.report_id = 'Rfed6481f-b349-44c0-b6cb-72a4219efbc6'
        self.mock_benign_scan_result.scan_id = 'fed6481f-b349-44c0-b6cb-72a4219efbc6'
        self.mock_benign_scan_result.profile_id = 'f5fc6a93-e739-4afd-a6b6-40b307555efc'
        self.mock_benign_scan_result.profile_name = 'stg-wf-dlp'
        self.mock_benign_scan_result.category = 'benign'
        self.mock_benign_scan_result.action = 'allow'
        
        self.mock_malicious_scan_result = Mock()
        self.mock_malicious_scan_result.report_id = 'R9b6ff47b-7dc2-4bab-97a7-67962c6c2c3e'
        self.mock_malicious_scan_result.scan_id = '9b6ff47b-7dc2-4bab-97a7-67962c6c2c3e'
        self.mock_malicious_scan_result.profile_id = 'f5fc6a93-e739-4afd-a6b6-40b307555efc'
        self.mock_malicious_scan_result.profile_name = 'stg-wf-dlp'
        self.mock_malicious_scan_result.category = 'malicious'
        self.mock_malicious_scan_result.action = 'block'

    async def asyncTearDown(self):
        # Clean up temp file
        if os.path.exists(self.temp_config_file.name):
            os.unlink(self.temp_config_file.name)
        
        # Clean up any remaining tasks
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    # A. 初始化相关测试
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.DownstreamMcpClient')
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.SecurityScanner')
    async def test_initialize_success(self, mock_security_scanner, mock_downstream_client):
        """测试正常初始化流程"""
        # Setup mocks
        mock_client_instance = AsyncMock()
        mock_client_instance.initialize = AsyncMock()
        mock_client_instance.cleanup = AsyncMock()
        mock_client_instance.list_tools = AsyncMock(return_value=[])
        mock_downstream_client.return_value = mock_client_instance
        
        mock_scanner_instance = Mock()
        mock_security_scanner.return_value = mock_scanner_instance
        
        # Create relay and initialize
        relay = PanSecurityRelay(
            config_path=self.temp_config_file.name,
            tool_registry_cache_expiry=300,
            max_downstream_servers=10,
            max_downstream_tools=100
        )
        
        await relay.initialize()
        
        # Verify initialization calls
        self.assertIsNotNone(relay.security_scanner)
        self.assertEqual(len(relay.servers), 3)  # pan-aisecurity, sqlite, weather
        mock_client_instance.initialize.assert_called()
        mock_client_instance.cleanup.assert_called()

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.Configuration')
    async def test_initialize_invalid_config(self, mock_configuration):
        """测试配置文件无效"""
        mock_config_instance = Mock()
        mock_config_instance.load_config.side_effect = Exception("Invalid JSON format")
        mock_configuration.return_value = mock_config_instance
        
        relay = PanSecurityRelay(
            config_path="invalid_config.json",
            tool_registry_cache_expiry=300,
            max_downstream_servers=10,
            max_downstream_tools=100
        )
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await relay.initialize()
        
        self.assertEqual(ErrorType.INVALID_CONFIGURATION, context.exception.error_type)
        self.assertTrue("Could not load configuration" in str(context.exception))

    async def test_initialize_missing_security_server(self):
        """测试缺少安全服务器配置"""
        # Create config without pan-aisecurity server
        config_without_security = {
            "mcpServers": {
                "sqlite": {
                    "command": "python",
                    "args": ["/Users/test/sqlite_server.py"]
                }
            }
        }
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(config_without_security, temp_file)
        temp_file.close()
        
        try:
            relay = PanSecurityRelay(
                config_path=temp_file.name,
                tool_registry_cache_expiry=300,
                max_downstream_servers=10,
                max_downstream_tools=100
            )
            
            with self.assertRaises(AISecMcpRelayException) as context:
                await relay.initialize()
            
            self.assertEqual(ErrorType.INVALID_CONFIGURATION, context.exception.error_type)
            self.assertTrue("Missing pan-aisecurity mcp server" in str(context.exception))
        finally:
            os.unlink(temp_file.name)

    async def test_initialize_exceed_max_servers(self):
        """测试超过最大服务器数量限制"""
        # Create config with too many servers
        config_too_many_servers = {
            "mcpServers": {
                f"server{i}": {
                    "command": "python",
                    "args": [f"/Users/test/server{i}.py"]
                } for i in range(6)  # 6 servers
            }
        }
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(config_too_many_servers, temp_file)
        temp_file.close()
        
        try:
            relay = PanSecurityRelay(
                config_path=temp_file.name,
                tool_registry_cache_expiry=300,
                max_downstream_servers=5,  # Set max to 5
                max_downstream_tools=100
            )
            
            with self.assertRaises(AISecMcpRelayException) as context:
                await relay.initialize()
            
            self.assertEqual(ErrorType.INVALID_CONFIGURATION, context.exception.error_type)
            self.assertTrue("MCP servers configuration limit exceeded" in str(context.exception))
        finally:
            os.unlink(temp_file.name)

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.DownstreamMcpClient')
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.SecurityScanner')
    async def test_initialize_exceed_max_tools(self, mock_security_scanner, mock_downstream_client):
        """测试超过最大工具数量限制"""
        # Setup mocks to return many tools
        mock_client_instance = AsyncMock()
        mock_client_instance.initialize = AsyncMock()
        mock_client_instance.cleanup = AsyncMock()
        
        # Create 6 mock tools to exceed limit of 5
        mock_tools = []
        for i in range(6):
            mock_tool = Mock()
            mock_tool.name = f"tool_{i}"
            mock_tool.description = f"Tool {i} description"
            mock_tool.inputSchema = {"type": "object", "properties": {}}
            mock_tool.annotations = None
            mock_tool.model_dump = Mock(return_value={
                'name': f"tool_{i}",
                'description': f"Tool {i} description",
                'inputSchema': {"type": "object", "properties": {}},
                'annotations': None
            })
            mock_tools.append(mock_tool)
        
        mock_client_instance.list_tools = AsyncMock(return_value=mock_tools)
        mock_downstream_client.return_value = mock_client_instance
        
        # 关键修改：正确设置 SecurityScanner mock
        mock_scanner_instance = Mock()
        mock_scanner_instance.scan_tool = AsyncMock(return_value=self.mock_benign_scan_result)
        mock_scanner_instance.should_block = Mock(return_value=False)
        mock_security_scanner.return_value = mock_scanner_instance
        
        relay = PanSecurityRelay(
            config_path=self.temp_config_file.name,
            tool_registry_cache_expiry=300,
            max_downstream_servers=10,
            max_downstream_tools=5  # Set max tools to 5
        )
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await relay.initialize()
        
        self.assertEqual(ErrorType.INVALID_CONFIGURATION, context.exception.error_type)
        self.assertTrue("Tools limit exceeded" in str(context.exception))


    # B. 配置加载相关测试
    async def test_load_config_success(self):
        """测试正常加载配置"""
        relay = PanSecurityRelay(
            config_path=self.temp_config_file.name,
            tool_registry_cache_expiry=300,
            max_downstream_servers=10,
            max_downstream_tools=100
        )
        
        servers_config = relay._load_config()
        
        self.assertIsInstance(servers_config, dict)
        self.assertIn("pan-aisecurity", servers_config)
        self.assertIn("sqlite", servers_config)
        self.assertIn("weather", servers_config)
        self.assertEqual(len(servers_config), 3)

    async def test_load_config_file_not_found(self):
        """测试配置文件不存在"""
        relay = PanSecurityRelay(
            config_path="nonexistent_config.json",
            tool_registry_cache_expiry=300,
            max_downstream_servers=10,
            max_downstream_tools=100
        )
        
        with self.assertRaises(AISecMcpRelayException) as context:
            relay._load_config()
        
        self.assertEqual(ErrorType.INVALID_CONFIGURATION, context.exception.error_type)
        self.assertTrue("Could not load configuration" in str(context.exception))

    async def test_load_config_invalid_format(self):
        """测试配置格式错误"""
        # Create invalid JSON config
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        temp_file.write("invalid json content")
        temp_file.close()
        
        try:
            relay = PanSecurityRelay(
                config_path=temp_file.name,
                tool_registry_cache_expiry=300,
                max_downstream_servers=10,
                max_downstream_tools=100
            )
            
            with self.assertRaises(AISecMcpRelayException) as context:
                relay._load_config()
            
            self.assertEqual(ErrorType.INVALID_CONFIGURATION, context.exception.error_type)
            self.assertTrue("Could not load configuration" in str(context.exception))
        finally:
            os.unlink(temp_file.name)

    async def test_load_config_empty_servers(self):
        """测试空的服务器配置"""
        # Create config with empty servers
        empty_config = {"mcpServers": {}}
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(empty_config, temp_file)
        temp_file.close()
        
        try:
            relay = PanSecurityRelay(
                config_path=temp_file.name,
                tool_registry_cache_expiry=300,
                max_downstream_servers=10,
                max_downstream_tools=100
            )
            
            with self.assertRaises(AISecMcpRelayException) as context:
                relay._load_config()
            
            self.assertEqual(ErrorType.INVALID_CONFIGURATION, context.exception.error_type)
            self.assertTrue("No MCP servers configured" in str(context.exception))
        finally:
            os.unlink(temp_file.name)

    # C. 安全扫描器相关测试
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.DownstreamMcpClient')
    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.SecurityScanner')
    async def test_update_security_scanner_success(self, mock_security_scanner, mock_downstream_client):
        """测试正常初始化安全扫描器"""
        # Setup mocks
        mock_client_instance = AsyncMock()
        mock_client_instance.initialize = AsyncMock()
        mock_client_instance.cleanup = AsyncMock()
        mock_downstream_client.return_value = mock_client_instance
        
        mock_scanner_instance = Mock()
        mock_security_scanner.return_value = mock_scanner_instance
        
        relay = PanSecurityRelay(
            config_path=self.temp_config_file.name,
            tool_registry_cache_expiry=300,
            max_downstream_servers=10,
            max_downstream_tools=100
        )
        
        servers_config = relay._load_config()
        await relay._update_security_scanner(servers_config)
        
        # Verify security scanner was created
        self.assertIsNotNone(relay.security_scanner)
        self.assertIn(SECURITY_SERVER_NAME, relay.servers)
        mock_client_instance.initialize.assert_called_once()
        mock_client_instance.cleanup.assert_called_once()
        mock_security_scanner.assert_called_once_with(mock_client_instance)

    @patch('pan_aisecurity_mcp.mcp_relay.pan_security_relay.DownstreamMcpClient')
    async def test_update_security_scanner_missing_server(self, mock_downstream_client):
        """测试缺少安全服务器"""
        # Create config without pan-aisecurity server
        config_without_security = {
            "sqlite": {
                "command": "python",
                "args": ["/Users/test/sqlite_server.py"]
            },
            "weather": {
                "command": "python",
                "args": ["/Users/test/weather_server.py"]
            }
        }
        
        relay = PanSecurityRelay(
            config_path=self.temp_config_file.name,
            tool_registry_cache_expiry=300,
            max_downstream_servers=10,
            max_downstream_tools=100
        )
        
        with self.assertRaises(AISecMcpRelayException) as context:
            await relay._update_security_scanner(config_without_security)
        
        self.assertEqual(ErrorType.INVALID_CONFIGURATION, context.exception.error_type)
        self.assertTrue("Missing pan-aisecurity mcp server" in str(context.exception))
        self.assertIsNone(relay.security_scanner)


if __name__ == "__main__":
    unittest.main()
