"""
Unit tests for the tool_registry module.

This module contains comprehensive tests for the ToolRegistry class using
simulated external tools for testing purposes.
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from typing import List

from pan_aisecurity_mcp.mcp_relay.tool_registry import ToolRegistry
from pan_aisecurity_mcp.mcp_relay.tool import InternalTool, ToolState
from pan_aisecurity_mcp.mcp_relay.exceptions import AISecMcpRelayException, ErrorType
from pan_aisecurity_mcp.mcp_relay.constants import TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT, UNIX_EPOCH


class TestToolRegistry:
    """Test suite for ToolRegistry class using simulated external tools."""

    @pytest.fixture
    def echo_tool(self):
        """Create echo tool that returns input."""
        return InternalTool(
            name="echo_tool",
            description="Echo back the input text",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {"type": "string"}
                },
                "required": ["text"]
            },
            server_name="test-server",
            state=ToolState.ENABLED
        )

    @pytest.fixture
    def error_all_tool(self):
        """Create tool that always returns isError=True."""
        return InternalTool(
            name="error_all_tool",
            description="Always returns error response",
            inputSchema={
                "type": "object",
                "properties": {
                    "input": {"type": "string"}
                }
            },
            server_name="test-server",
            state=ToolState.ENABLED
        )

    @pytest.fixture
    def slow_response_tool(self):
        """Create latency simulator tool."""
        return InternalTool(
            name="slow_response_tool",
            description="Simulates slow response with intentional delay",
            inputSchema={
                "type": "object",
                "properties": {
                    "delay_seconds": {"type": "number", "minimum": 0},
                    "content": {"type": "string"}
                }
            },
            server_name="performance-server",
            state=ToolState.ENABLED
        )

    @pytest.fixture
    def fixed_response_tool(self):
        """Create tool that returns fixed preset results."""
        return InternalTool(
            name="fixed_response_tool",
            description="Returns predefined fixed response",
            inputSchema={
                "type": "object",
                "properties": {
                    "response_type": {
                        "type": "string",
                        "enum": ["success", "warning", "info"]
                    }
                }
            },
            server_name="mock-server",
            state=ToolState.ENABLED
        )

    @pytest.fixture
    def passthrough_tool(self):
        """Create tool that does nothing and returns directly."""
        return InternalTool(
            name="passthrough_tool",
            description="Passthrough tool that returns input unchanged",
            inputSchema={
                "type": "object",
                "properties": {}
            },
            server_name="utility-server",
            state=ToolState.ENABLED
        )

    @pytest.fixture
    def failing_tool(self):
        """Create tool that intentionally fails or throws exceptions."""
        return InternalTool(
            name="failing_tool",
            description="Intentionally fails with errors",
            inputSchema={
                "type": "object",
                "properties": {
                    "failure_mode": {
                        "type": "string",
                        "enum": ["exception", "error_response", "timeout"]
                    }
                }
            },
            server_name="test-server",
            state=ToolState.DISABLED_ERROR
        )

    @pytest.fixture
    def sample_tool_list(self, echo_tool, error_all_tool, slow_response_tool,
                         fixed_response_tool, passthrough_tool, failing_tool):
        """Create list of sample tools for testing."""
        return [
            echo_tool,
            error_all_tool,
            slow_response_tool,
            fixed_response_tool,
            passthrough_tool,
            failing_tool
        ]

    def test_tool_registry_initialization_default_expiry(self):
        """Test ToolRegistry initialization with default cache expiry."""
        registry = ToolRegistry()

        assert registry._internal_tool_list == []
        assert registry._available_tool_list == []
        assert registry._hash_to_tool_map == {}
        assert registry._last_updated_at == UNIX_EPOCH
        assert registry._expiry_in_seconds == TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT

    def test_tool_registry_initialization_custom_expiry(self):
        """Test ToolRegistry initialization with custom cache expiry."""
        custom_expiry = 1800  # 30 minutes
        registry = ToolRegistry(tool_registry_cache_expiry=custom_expiry)

        assert registry._expiry_in_seconds == custom_expiry

    def test_tool_registry_initialization_invalid_expiry(self):
        """Test ToolRegistry initialization with invalid cache expiry."""
        with pytest.raises(AISecMcpRelayException) as exc_info:
            ToolRegistry(tool_registry_cache_expiry=0)

        assert exc_info.value.error_type == ErrorType.VALIDATION_ERROR
        assert "positive integer" in str(exc_info.value)

        with pytest.raises(AISecMcpRelayException) as exc_info:
            ToolRegistry(tool_registry_cache_expiry=-100)

        assert exc_info.value.error_type == ErrorType.VALIDATION_ERROR

    @patch('pan_aisecurity_mcp.mcp_relay.tool_registry.logger')
    def test_tool_registry_initialization_logging(self, mock_logger):
        """Test that initialization logs cache expiry information."""
        expiry = 3600
        ToolRegistry(tool_registry_cache_expiry=expiry)

        mock_logger.info.assert_called_with(
            "Tool registry initialized with cache expiry %d seconds.",
            expiry
        )

    def test_update_registry_with_simulated_tools(self, sample_tool_list):
        """Test updating registry with simulated tools."""
        registry = ToolRegistry()

        with patch('pan_aisecurity_mcp.mcp_relay.tool_registry.datetime') as mock_datetime:
            mock_now = datetime(2024, 1, 15, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            registry.update_registry(sample_tool_list)

        assert len(registry._internal_tool_list) == 6
        assert len(registry._available_tool_list) == 5  # 5 enabled tools (failing_tool is disabled)
        assert len(registry._hash_to_tool_map) == 6
        assert registry._last_updated_at == mock_now

    def test_update_registry_none_tool_list(self):
        """Test updating registry with None tool list."""
        registry = ToolRegistry()

        with pytest.raises(AISecMcpRelayException) as exc_info:
            registry.update_registry(None)

        assert exc_info.value.error_type == ErrorType.VALIDATION_ERROR
        assert "cannot be None" in str(exc_info.value)

    def test_update_registry_invalid_tool_list_type(self):
        """Test updating registry with invalid tool list type."""
        registry = ToolRegistry()

        with pytest.raises(AISecMcpRelayException) as exc_info:
            registry.update_registry("not_a_list")

        assert exc_info.value.error_type == ErrorType.VALIDATION_ERROR
        assert "must be a list" in str(exc_info.value)

    def test_update_registry_exception_handling(self, sample_tool_list):
        """Test registry update exception handling."""
        registry = ToolRegistry()

        # Mock an exception during update
        with patch.object(registry, '_update_available_tools', side_effect=Exception("Test error")):
            with pytest.raises(AISecMcpRelayException) as exc_info:
                registry.update_registry(sample_tool_list)

            assert exc_info.value.error_type == ErrorType.TOOL_REGISTRY_ERROR
            assert "Failed to update tool registry" in str(exc_info.value)

    @patch('pan_aisecurity_mcp.mcp_relay.tool_registry.logger')
    def test_update_registry_logging(self, mock_logger, sample_tool_list):
        """Test that registry update logs information."""
        registry = ToolRegistry()

        with patch('pan_aisecurity_mcp.mcp_relay.tool_registry.datetime') as mock_datetime:
            mock_now = datetime(2024, 1, 15, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            registry.update_registry(sample_tool_list)

        mock_logger.info.assert_called_with(
            "Tool registry updated at %s with %d tools (%d available).",
            mock_now,
            6,  # total tools
            5  # available tools (excluding failing_tool which is disabled)
        )

    def test_update_available_tools_filtering(self, sample_tool_list):
        """Test that _update_available_tools filters enabled tools correctly."""
        registry = ToolRegistry()
        registry._internal_tool_list = sample_tool_list

        registry._update_available_tools()

        # Should only include enabled tools
        assert len(registry._available_tool_list) == 5
        for tool in registry._available_tool_list:
            assert tool.state == ToolState.ENABLED

        # Check specific tools are included/excluded
        tool_names = [tool.name for tool in registry._available_tool_list]
        assert "echo_tool" in tool_names
        assert "error_all_tool" in tool_names
        assert "slow_response_tool" in tool_names
        assert "fixed_response_tool" in tool_names
        assert "passthrough_tool" in tool_names
        assert "failing_tool" not in tool_names  # This one is disabled

    def test_update_hash_mapping(self, sample_tool_list):
        """Test that _update_hash_mapping creates correct hash mappings."""
        registry = ToolRegistry()
        registry._internal_tool_list = sample_tool_list

        registry._update_hash_mapping()

        assert len(registry._hash_to_tool_map) == 6

        # Verify each tool can be found by its hash
        for tool in sample_tool_list:
            assert tool.md5_hash in registry._hash_to_tool_map
            assert registry._hash_to_tool_map[tool.md5_hash] == tool

    def test_update_hash_mapping_with_empty_hash(self):
        """Test hash mapping with tool that has empty hash."""
        registry = ToolRegistry()

        # Create tool with empty hash (mock scenario)
        tool_with_empty_hash = InternalTool(
            name="test_tool",
            description="Test tool",
            inputSchema={},
            server_name="test_server"
        )
        tool_with_empty_hash.md5_hash = ""  # Force empty hash

        registry._internal_tool_list = [tool_with_empty_hash]
        registry._update_hash_mapping()

        # Tool with empty hash should not be in mapping
        assert len(registry._hash_to_tool_map) == 0

    def test_is_registry_outdated_fresh(self):
        """Test is_registry_outdated with fresh registry."""
        registry = ToolRegistry(tool_registry_cache_expiry=3600)  # 1 hour

        with patch('pan_aisecurity_mcp.mcp_relay.tool_registry.datetime') as mock_datetime:
            mock_now = datetime(2024, 1, 15, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            registry._last_updated_at = mock_now - timedelta(minutes=30)  # 30 minutes ago

            assert not registry.is_registry_outdated()

    def test_is_registry_outdated_expired(self):
        """Test is_registry_outdated with expired registry."""
        registry = ToolRegistry(tool_registry_cache_expiry=3600)  # 1 hour

        with patch('pan_aisecurity_mcp.mcp_relay.tool_registry.datetime') as mock_datetime:
            mock_now = datetime(2024, 1, 15, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            registry._last_updated_at = mock_now - timedelta(hours=2)  # 2 hours ago

            assert registry.is_registry_outdated()

    def test_is_registry_outdated_exactly_expired(self):
        """Test is_registry_outdated at exact expiry time."""
        registry = ToolRegistry(tool_registry_cache_expiry=3600)  # 1 hour

        with patch('pan_aisecurity_mcp.mcp_relay.tool_registry.datetime') as mock_datetime:
            mock_now = datetime(2024, 1, 15, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            registry._last_updated_at = mock_now - timedelta(seconds=3600)  # Exactly 1 hour ago

            assert not registry.is_registry_outdated()  # Should be false at exact boundary

    def test_get_available_tools(self, sample_tool_list):
        """Test retrieving available tools."""
        registry = ToolRegistry()
        registry.update_registry(sample_tool_list)

        available_tools = registry.get_available_tools()

        assert len(available_tools) == 5
        for tool in available_tools:
            assert tool.state == ToolState.ENABLED

        # Verify it returns the same list reference for efficiency
        assert available_tools is registry._available_tool_list

    def test_get_all_tools(self, sample_tool_list):
        """Test retrieving all tools regardless of state."""
        registry = ToolRegistry()
        registry.update_registry(sample_tool_list)

        all_tools = registry.get_all_tools()

        assert len(all_tools) == 6
        assert all_tools is registry._internal_tool_list

        # Should include both enabled and disabled tools
        states = [tool.state for tool in all_tools]
        assert ToolState.ENABLED in states
        assert ToolState.DISABLED_ERROR in states

    def test_get_tool_by_hash_found(self, echo_tool):
        """Test retrieving tool by hash when tool exists."""
        registry = ToolRegistry()
        registry.update_registry([echo_tool])

        found_tool = registry.get_tool_by_hash(echo_tool.md5_hash)

        assert found_tool is not None
        assert found_tool == echo_tool
        assert found_tool.name == "echo_tool"

    def test_get_tool_by_hash_not_found(self):
        """Test retrieving tool by hash when tool doesn't exist."""
        registry = ToolRegistry()
        registry.update_registry([])

        found_tool = registry.get_tool_by_hash("nonexistent_hash")

        assert found_tool is None

    def test_get_tool_by_hash_empty_hash(self):
        """Test retrieving tool by empty hash."""
        registry = ToolRegistry()

        found_tool = registry.get_tool_by_hash("")

        assert found_tool is None

    def test_get_tool_by_hash_invalid_type(self):
        """Test retrieving tool by hash with invalid type."""
        registry = ToolRegistry()

        with pytest.raises(AISecMcpRelayException) as exc_info:
            registry.get_tool_by_hash(123)

        assert exc_info.value.error_type == ErrorType.VALIDATION_ERROR
        assert "must be a string" in str(exc_info.value)

    def test_get_server_tool_map(self, sample_tool_list):
        """Test grouping tools by server name."""
        registry = ToolRegistry()
        registry.update_registry(sample_tool_list)

        server_tool_map = registry.get_server_tool_map()

        assert len(server_tool_map) == 4  # Four different servers
        assert "test-server" in server_tool_map
        assert "performance-server" in server_tool_map
        assert "mock-server" in server_tool_map
        assert "utility-server" in server_tool_map

        # Check test-server tools (echo_tool, error_all_tool, failing_tool)
        test_server_tools = server_tool_map["test-server"]
        assert len(test_server_tools) == 3
        tool_names = [tool.name for tool in test_server_tools]
        assert "echo_tool" in tool_names
        assert "error_all_tool" in tool_names
        assert "failing_tool" in tool_names

        # Check other servers have one tool each
        assert len(server_tool_map["performance-server"]) == 1
        assert len(server_tool_map["mock-server"]) == 1
        assert len(server_tool_map["utility-server"]) == 1

    def test_get_server_tool_map_empty_registry(self):
        """Test server tool map with empty registry."""
        registry = ToolRegistry()

        server_tool_map = registry.get_server_tool_map()

        assert server_tool_map == {}

    def test_get_server_tool_map_json(self, sample_tool_list):
        """Test getting server tool map as JSON."""
        registry = ToolRegistry()
        registry.update_registry(sample_tool_list)

        json_map = registry.get_server_tool_map_json()

        # Should be valid JSON
        parsed_json = json.loads(json_map)

        assert "test-server" in parsed_json
        assert "performance-server" in parsed_json
        assert "mock-server" in parsed_json
        assert "utility-server" in parsed_json

        # Each server's tools should be JSON strings
        test_server_tools_json = parsed_json["test-server"]
        test_server_tools = json.loads(test_server_tools_json)

        assert len(test_server_tools) == 3
        assert all("name" in tool for tool in test_server_tools)
        assert all("md5_hash" in tool for tool in test_server_tools)

    def test_get_server_tool_map_json_serialization_error(self, sample_tool_list):
        """Test server tool map JSON with serialization error."""
        registry = ToolRegistry()
        registry.update_registry(sample_tool_list)

        # Mock to_dict to raise exception
        with patch.object(InternalTool, 'to_dict', side_effect=AttributeError("Test error")):
            with pytest.raises(AISecMcpRelayException) as exc_info:
                registry.get_server_tool_map_json()

            assert exc_info.value.error_type == ErrorType.TOOL_REGISTRY_ERROR
            assert "Tool serialization failed" in str(exc_info.value)

    def test_get_registry_stats(self, sample_tool_list):
        """Test getting registry statistics."""
        registry = ToolRegistry(tool_registry_cache_expiry=1800)

        with patch('pan_aisecurity_mcp.mcp_relay.tool_registry.datetime') as mock_datetime:
            mock_now = datetime(2024, 1, 15, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            registry.update_registry(sample_tool_list)

            # Make registry appear outdated
            registry._last_updated_at = mock_now - timedelta(seconds=2000)

            stats = registry.get_registry_stats()

        assert stats["total_tools"] == 6
        assert stats["available_tools"] == 5
        assert stats["server_count"] == 4
        assert stats["last_updated"] == registry._last_updated_at.isoformat()
        assert stats["is_outdated"] == True
        assert stats["cache_expiry_seconds"] == 1800

    def test_get_registry_stats_fresh_registry(self, sample_tool_list):
        """Test registry statistics with fresh registry."""
        registry = ToolRegistry()

        with patch('pan_aisecurity_mcp.mcp_relay.tool_registry.datetime') as mock_datetime:
            mock_now = datetime(2024, 1, 15, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            registry.update_registry(sample_tool_list)

            stats = registry.get_registry_stats()

        assert stats["is_outdated"] == False

    def test_clear_registry(self, sample_tool_list):
        """Test clearing the registry."""
        registry = ToolRegistry()
        registry.update_registry(sample_tool_list)

        # Verify registry has data
        assert len(registry._internal_tool_list) > 0
        assert len(registry._available_tool_list) > 0
        assert len(registry._hash_to_tool_map) > 0
        assert registry._last_updated_at != UNIX_EPOCH

        registry.clear_registry()

        # Verify registry is cleared
        assert len(registry._internal_tool_list) == 0
        assert len(registry._available_tool_list) == 0
        assert len(registry._hash_to_tool_map) == 0
        assert registry._last_updated_at == UNIX_EPOCH

    @patch('pan_aisecurity_mcp.mcp_relay.tool_registry.logger')
    def test_clear_registry_logging(self, mock_logger):
        """Test that clear registry logs information."""
        registry = ToolRegistry()
        registry.clear_registry()

        mock_logger.info.assert_called_with("Tool registry cleared.")

    def test_len_operator(self, sample_tool_list):
        """Test __len__ operator for registry."""
        registry = ToolRegistry()

        assert len(registry) == 0

        registry.update_registry(sample_tool_list)

        assert len(registry) == 6

    def test_contains_operator(self, echo_tool):
        """Test __contains__ operator for registry."""
        registry = ToolRegistry()

        assert echo_tool.md5_hash not in registry

        registry.update_registry([echo_tool])

        assert echo_tool.md5_hash in registry
        assert "nonexistent_hash" not in registry

    def test_repr_operator(self, sample_tool_list):
        """Test __repr__ operator for registry."""
        registry = ToolRegistry()

        with patch('pan_aisecurity_mcp.mcp_relay.tool_registry.datetime') as mock_datetime:
            mock_now = datetime(2024, 1, 15, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            registry.update_registry(sample_tool_list)

            repr_str = repr(registry)

        expected_str = (
            f"ToolRegistry(total_tools=6, "
            f"available_tools=5, "
            f"last_updated={mock_now})"
        )
        assert repr_str == expected_str

    def test_registry_workflow_integration(self, sample_tool_list):
        """Test complete registry workflow integration."""
        registry = ToolRegistry(tool_registry_cache_expiry=60)

        # Initial state
        assert len(registry) == 0
        assert registry.is_registry_outdated()

        # Update registry
        registry.update_registry(sample_tool_list)

        # Verify registry state
        assert len(registry) == 6
        assert len(registry.get_available_tools()) == 5
        assert not registry.is_registry_outdated()

        # Test tool lookup
        echo_tool = next(
            tool for tool in sample_tool_list
            if tool.name == "echo_tool"
        )
        found_tool = registry.get_tool_by_hash(echo_tool.md5_hash)
        assert found_tool == echo_tool

        # Test server mapping
        server_map = registry.get_server_tool_map()
        assert len(server_map) == 4

        # Test statistics
        stats = registry.get_registry_stats()
        assert stats["total_tools"] == 6
        assert stats["available_tools"] == 5

        # Clear and verify
        registry.clear_registry()
        assert len(registry) == 0
        assert len(registry.get_available_tools()) == 0

    def test_concurrent_updates_scenario(self, sample_tool_list):
        """Test scenario with multiple registry updates."""
        registry = ToolRegistry()

        # First update with subset of tools
        registry.update_registry(sample_tool_list[:3])
        assert len(registry) == 3

        # Second update with different tools
        registry.update_registry(sample_tool_list[3:])
        assert len(registry) == 3

        # Third update with all tools
        registry.update_registry(sample_tool_list)
        assert len(registry) == 6

        # Verify hash mappings are correct after multiple updates
        for tool in sample_tool_list:
            found_tool = registry.get_tool_by_hash(tool.md5_hash)
            assert found_tool == tool

    def test_performance_considerations_large_tool_set(self):
        """Test registry performance with large tool set."""
        registry = ToolRegistry()

        # Create large set of simulated tools
        large_tool_list = []
        tool_types = ["echo", "error", "slow", "fixed", "passthrough", "failing"]

        for i in range(100):
            tool_type = tool_types[i % len(tool_types)]
            state = ToolState.ENABLED if i % 2 == 0 else ToolState.DISABLED_ERROR

            tool = InternalTool(
                name=f"{tool_type}_tool_{i}",
                description=f"Simulated {tool_type} tool number {i}",
                inputSchema={"type": "object"},
                server_name=f"server_{i % 10}",  # 10 different servers
                state=state
            )
            large_tool_list.append(tool)

        # Update registry
        registry.update_registry(large_tool_list)

        # Verify operations are efficient
        assert len(registry) == 100
        assert len(registry.get_available_tools()) == 50  # Half are enabled

        # Hash lookup should be O(1)
        first_tool = large_tool_list[0]
        found_tool = registry.get_tool_by_hash(first_tool.md5_hash)
        assert found_tool == first_tool

        # Server mapping should group correctly
        server_map = registry.get_server_tool_map()
        assert len(server_map) == 10  # 10 different servers
        for server_tools in server_map.values():
            assert len(server_tools) == 10  # 10 tools per server

    def test_mixed_tool_states_handling(self):
        """Test registry handling of tools with different states."""
        registry = ToolRegistry()

        # Create tools with different states
        enabled_tool = InternalTool(
            name="enabled_echo_tool",
            description="Enabled echo tool",
            inputSchema={"type": "object"},
            server_name="test-server",
            state=ToolState.ENABLED
        )

        disabled_tool = InternalTool(
            name="disabled_error_tool",
            description="Disabled error tool",
            inputSchema={"type": "object"},
            server_name="test-server",
            state=ToolState.DISABLED_ERROR
        )

        tools = [enabled_tool, disabled_tool]
        registry.update_registry(tools)

        # Test filtering
        assert len(registry.get_all_tools()) == 2
        assert len(registry.get_available_tools()) == 1
        assert registry.get_available_tools()[0].state == ToolState.ENABLED

        # Test hash mapping includes all tools regardless of state
        assert len(registry._hash_to_tool_map) == 2
        assert enabled_tool.md5_hash in registry._hash_to_tool_map
        assert disabled_tool.md5_hash in registry._hash_to_tool_map

    def test_tool_registry_edge_cases(self):
        """Test edge cases for tool registry operations."""
        registry = ToolRegistry()

        # Test with empty tool list
        registry.update_registry([])
        assert len(registry) == 0
        assert len(registry.get_available_tools()) == 0
        assert registry.get_server_tool_map() == {}

        # Test statistics with empty registry
        stats = registry.get_registry_stats()
        assert stats["total_tools"] == 0
        assert stats["available_tools"] == 0
        assert stats["server_count"] == 0

        # Test JSON serialization with empty registry
        json_map = registry.get_server_tool_map_json()
        parsed = json.loads(json_map)
        assert parsed == {}
