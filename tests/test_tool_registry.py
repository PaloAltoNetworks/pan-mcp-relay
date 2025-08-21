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
Unit tests for the tool_registry module.

This module contains comprehensive tests for the ToolRegistry class using
simulated tools for testing purposes.
"""

import json
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from pan_mcp_relay.constants import TOOL_REGISTRY_CACHE_TTL_DEFAULT, UNIX_EPOCH
from pan_mcp_relay.exceptions import (
    McpRelayBaseError,
    McpRelayToolRegistryError,
    McpRelayValidationError,
)
from pan_mcp_relay.tool import InternalTool, ToolState
from pan_mcp_relay.tool_registry import ToolRegistry


@pytest.fixture
def echo_tool():
    """Create echo tool that returns input."""
    return InternalTool(
        name="echo_tool",
        description="Echo back the input text",
        inputSchema={"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
        server_name="test-server",
        state=ToolState.ENABLED,
    )


@pytest.fixture
def error_all_tool():
    """Create tool that always returns isError=True."""
    return InternalTool(
        name="error_all_tool",
        description="Always returns error response",
        inputSchema={"type": "object", "properties": {"input": {"type": "string"}}},
        server_name="test-server",
        state=ToolState.ENABLED,
    )


@pytest.fixture
def slow_response_tool():
    """Create latency simulator tool."""
    return InternalTool(
        name="slow_response_tool",
        description="Simulates slow response with intentional delay",
        inputSchema={
            "type": "object",
            "properties": {"delay_seconds": {"type": "number", "minimum": 0}, "content": {"type": "string"}},
        },
        server_name="performance-server",
        state=ToolState.ENABLED,
    )


@pytest.fixture
def fixed_response_tool():
    """Create tool that returns fixed preset results."""
    return InternalTool(
        name="fixed_response_tool",
        description="Returns predefined fixed response",
        inputSchema={
            "type": "object",
            "properties": {"response_type": {"type": "string", "enum": ["success", "warning", "info"]}},
        },
        server_name="mock-server",
        state=ToolState.ENABLED,
    )


@pytest.fixture
def passthrough_tool():
    """Create tool that does nothing and returns directly."""
    return InternalTool(
        name="passthrough_tool",
        description="Passthrough tool that returns input unchanged",
        inputSchema={"type": "object", "properties": {}},
        server_name="utility-server",
        state=ToolState.ENABLED,
    )


@pytest.fixture
def failing_tool():
    """Create tool that intentionally fails or throws exceptions."""
    return InternalTool(
        name="failing_tool",
        description="Intentionally fails with errors",
        inputSchema={
            "type": "object",
            "properties": {"failure_mode": {"type": "string", "enum": ["exception", "error_response", "timeout"]}},
        },
        server_name="test-server",
        state=ToolState.DISABLED_ERROR,
    )


@pytest.fixture
def sample_tool_list(
    echo_tool, error_all_tool, slow_response_tool, fixed_response_tool, passthrough_tool, failing_tool
):
    """Create list of sample tools for testing."""
    return [echo_tool, error_all_tool, slow_response_tool, fixed_response_tool, passthrough_tool, failing_tool]


def test_tool_registry_initialization_default_expiry():
    """Test ToolRegistry initialization with default cache expiry."""
    registry = ToolRegistry()

    assert registry.tools == []
    assert registry.available_tools == []
    assert registry.tools_by_checksum == {}
    assert registry.last_update == UNIX_EPOCH
    assert registry.refresh_interval == TOOL_REGISTRY_CACHE_TTL_DEFAULT


def test_tool_registry_initialization_custom_expiry():
    """Test ToolRegistry initialization with custom cache expiry."""
    custom_expiry = 1800  # 30 minutes
    registry = ToolRegistry(tool_registry_cache_expiry=custom_expiry)

    assert registry.refresh_interval == custom_expiry


def test_tool_registry_initialization_invalid_expiry():
    """Test ToolRegistry initialization with invalid cache expiry."""
    with pytest.raises(McpRelayBaseError) as exc_info:
        ToolRegistry(tool_registry_cache_expiry=0)

    assert isinstance(exc_info.value, McpRelayValidationError)
    assert "positive integer" in str(exc_info.value)

    with pytest.raises(McpRelayBaseError) as exc_info:
        ToolRegistry(tool_registry_cache_expiry=-100)

    assert isinstance(exc_info.value, McpRelayValidationError)


@patch("pan_mcp_relay.tool_registry.logger")
def test_tool_registry_initialization_logging(mock_logger):
    """Test that initialization logs cache expiry information."""
    expiry = 3600
    ToolRegistry(tool_registry_cache_expiry=expiry)

    mock_logger.info.assert_called_with("Tool registry initialized with cache expiry %d seconds.", expiry)


def test_update_registry_with_simulated_tools(sample_tool_list):
    """Test updating registry with simulated tools."""
    registry = ToolRegistry()

    with patch("pan_mcp_relay.tool_registry.datetime") as mock_datetime:
        mock_now = datetime(2024, 1, 15, 12, 0, 0)
        mock_datetime.now.return_value = mock_now

        registry.update_registry(sample_tool_list)

    assert len(registry.tools) == 6
    assert len(registry.available_tools) == 5  # 5 enabled tools (failing_tool is disabled)
    assert len(registry.tools_by_checksum) == 6
    assert registry.last_update == mock_now


def test_update_registry_none_tool_list():
    """Test updating registry with None tool list."""
    registry = ToolRegistry()

    with pytest.raises(McpRelayBaseError) as exc_info:
        registry.update_registry(None)

    assert isinstance(exc_info.value, McpRelayValidationError)
    assert "cannot be None" in str(exc_info.value)


def test_update_registry_invalid_tool_list_type():
    """Test updating registry with invalid tool list type."""
    registry = ToolRegistry()

    with pytest.raises(McpRelayBaseError) as exc_info:
        registry.update_registry("not_a_list")

    assert isinstance(exc_info.value, McpRelayValidationError)
    assert "must be a list" in str(exc_info.value)


def test_update_registry_exception_handling(sample_tool_list):
    """Test registry update exception handling."""
    registry = ToolRegistry()

    # Mock an exception during update
    with patch.object(registry, "_update_available_tools", side_effect=Exception("Test error")):
        with pytest.raises(McpRelayBaseError) as exc_info:
            registry.update_registry(sample_tool_list)

        assert isinstance(exc_info.value, McpRelayToolRegistryError)
        assert "Failed to update tool registry" in str(exc_info.value)


@patch("pan_mcp_relay.tool_registry.logger")
def test_update_registry_logging(mock_logger, sample_tool_list):
    """Test that registry update logs information."""
    registry = ToolRegistry()

    with patch("pan_mcp_relay.tool_registry.datetime") as mock_datetime:
        mock_now = datetime(2024, 1, 15, 12, 0, 0)
        mock_datetime.now.return_value = mock_now

        registry.update_registry(sample_tool_list)

    mock_logger.info.assert_called_with(
        "Tool registry updated at %s with %d tools (%d available).",
        mock_now,
        6,  # total tools
        5,  # available tools (excluding failing_tool which is disabled)
    )


def test_update_available_tools_filtering(sample_tool_list):
    """Test that _update_available_tools filters enabled tools correctly."""
    registry = ToolRegistry()
    registry.tools = sample_tool_list

    registry.update_available_tools()

    # Should only include enabled tools
    assert len(registry.available_tools) == 5
    for tool in registry.available_tools:
        assert tool.state == ToolState.ENABLED

    # Check specific tools are included/excluded
    tool_names = [tool.name for tool in registry.available_tools]
    assert "echo_tool" in tool_names
    assert "error_all_tool" in tool_names
    assert "slow_response_tool" in tool_names
    assert "fixed_response_tool" in tool_names
    assert "passthrough_tool" in tool_names
    assert "failing_tool" not in tool_names  # This one is disabled


def test_update_hash_mapping(sample_tool_list):
    """Test that _update_hash_mapping creates correct hash mappings."""
    registry = ToolRegistry()
    registry.tools = sample_tool_list

    registry.update_hash_mapping()

    assert len(registry.tools_by_checksum) == 6

    # Verify each tool can be found by its hash
    for tool in sample_tool_list:
        assert tool.sha256_hash in registry.tools_by_checksum
        assert registry.tools_by_checksum[tool.sha256_hash] == tool


def test_update_hash_mapping_with_empty_hash():
    """Test hash mapping with tool that has empty hash."""
    registry = ToolRegistry()

    # Create tool with empty hash (mock scenario)
    tool_with_empty_hash = InternalTool(
        name="test_tool", description="Test tool", inputSchema={}, server_name="test_server"
    )
    tool_with_empty_hash.sha256_hash = ""  # Force empty hash

    registry.tools = [tool_with_empty_hash]
    registry.update_hash_mapping()

    # Tool with empty hash should not be in mapping
    assert len(registry.tools_by_checksum) == 0


def test_is_registry_outdated_fresh():
    """Test is_registry_outdated with fresh registry."""
    registry = ToolRegistry(tool_registry_cache_expiry=3600)  # 1 hour

    with patch("pan_mcp_relay.tool_registry.datetime") as mock_datetime:
        mock_now = datetime(2024, 1, 15, 12, 0, 0)
        mock_datetime.now.return_value = mock_now

        registry.last_update = mock_now - timedelta(minutes=30)  # 30 minutes ago

        assert not registry.is_registry_outdated()


def test_is_registry_outdated_expired():
    """Test is_registry_outdated with expired registry."""
    registry = ToolRegistry(tool_registry_cache_expiry=3600)  # 1 hour

    with patch("pan_mcp_relay.tool_registry.datetime") as mock_datetime:
        mock_now = datetime(2024, 1, 15, 12, 0, 0)
        mock_datetime.now.return_value = mock_now

        registry.last_update = mock_now - timedelta(hours=2)  # 2 hours ago

        assert registry.is_registry_outdated()


def test_is_registry_outdated_exactly_expired():
    """Test is_registry_outdated at exact expiry time."""
    registry = ToolRegistry(tool_registry_cache_expiry=3600)  # 1 hour

    with patch("pan_mcp_relay.tool_registry.datetime") as mock_datetime:
        mock_now = datetime(2024, 1, 15, 12, 0, 0)
        mock_datetime.now.return_value = mock_now

        registry.last_update = mock_now - timedelta(seconds=3600)  # Exactly 1 hour ago

        assert not registry.is_registry_outdated()  # Should be false at exact boundary


def test_get_available_tools(sample_tool_list):
    """Test retrieving available tools."""
    registry = ToolRegistry()
    registry.update_registry(sample_tool_list)

    available_tools = registry.get_available_tools()

    assert len(available_tools) == 5
    for tool in available_tools:
        assert tool.state == ToolState.ENABLED

    # Verify it returns the same list reference for efficiency
    assert available_tools is registry.available_tools


def test_get_all_tools(sample_tool_list):
    """Test retrieving all tools regardless of state."""
    registry = ToolRegistry()
    registry.update_registry(sample_tool_list)

    all_tools = registry.get_all_tools()

    assert len(all_tools) == 6
    assert all_tools is registry.tools

    # Should include both enabled and disabled tools
    states = [tool.state for tool in all_tools]
    assert ToolState.ENABLED in states
    assert ToolState.DISABLED_ERROR in states


def test_get_tool_by_hash_found(echo_tool):
    """Test retrieving tool by hash when tool exists."""
    registry = ToolRegistry()
    registry.update_registry([echo_tool])

    found_tool = registry.get_tool_by_hash(echo_tool.sha256_hash)

    assert found_tool is not None
    assert found_tool == echo_tool
    assert found_tool.name == "echo_tool"


def test_get_tool_by_hash_not_found():
    """Test retrieving tool by hash when tool doesn't exist."""
    registry = ToolRegistry()
    registry.update_registry([])

    found_tool = registry.get_tool_by_hash("nonexistent_hash")

    assert found_tool is None


def test_get_tool_by_hash_empty_hash():
    """Test retrieving tool by empty hash."""
    registry = ToolRegistry()

    found_tool = registry.get_tool_by_hash("")

    assert found_tool is None


def test_get_tool_by_hash_invalid_type():
    """Test retrieving tool by hash with invalid type."""
    registry = ToolRegistry()

    with pytest.raises(McpRelayBaseError) as exc_info:
        registry.get_tool_by_hash(123)

    assert isinstance(exc_info.value, McpRelayValidationError)
    assert "must be a string" in str(exc_info.value)


def test_get_server_tool_map(sample_tool_list):
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


def test_get_server_tool_map_empty_registry():
    """Test server tool map with empty registry."""
    registry = ToolRegistry()

    server_tool_map = registry.get_server_tool_map()

    assert server_tool_map == {}


def test_get_server_tool_map_json(sample_tool_list):
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

    # Each server's tools should be a list of tool dictionaries
    test_server_tools = parsed_json["test-server"]

    assert len(test_server_tools) == 3
    assert all("name" in tool for tool in test_server_tools)
    assert all("sha256_hash" in tool for tool in test_server_tools)


def test_get_server_tool_map_json_serialization_error(sample_tool_list):
    """Test server tool map JSON with serialization error."""
    registry = ToolRegistry()
    registry.update_registry(sample_tool_list)

    with patch.object(InternalTool, "model_dump", side_effect=AttributeError("Test error")):
        with pytest.raises(McpRelayToolRegistryError) as exc_info:
            registry.get_server_tool_map_json()

        assert isinstance(exc_info.value, McpRelayToolRegistryError)
        assert "Tool serialization failed" in str(exc_info.value)


def test_get_registry_stats(sample_tool_list):
    """Test getting registry statistics."""
    registry = ToolRegistry(tool_registry_cache_expiry=1800)

    with patch("pan_mcp_relay.tool_registry.datetime") as mock_datetime:
        mock_now = datetime(2024, 1, 15, 12, 0, 0)
        mock_datetime.now.return_value = mock_now

        registry.update_registry(sample_tool_list)

        # Make registry appear outdated
        registry.last_update = mock_now - timedelta(seconds=2000)

        stats = registry.get_registry_stats()

    assert stats["total_tools"] == 6
    assert stats["available_tools"] == 5
    assert stats["server_count"] == 4
    assert stats["last_updated"] == registry.last_update.isoformat()
    assert stats["is_outdated"]
    assert stats["cache_expiry_seconds"] == 1800


def test_get_registry_stats_fresh_registry(sample_tool_list):
    """Test registry statistics with fresh registry."""
    registry = ToolRegistry()

    with patch("pan_mcp_relay.tool_registry.datetime") as mock_datetime:
        mock_now = datetime(2024, 1, 15, 12, 0, 0)
        mock_datetime.now.return_value = mock_now

        registry.update_registry(sample_tool_list)

        stats = registry.get_registry_stats()

    assert not stats["is_outdated"]


def test_clear_registry(sample_tool_list):
    """Test clearing the registry."""
    registry = ToolRegistry()
    registry.update_registry(sample_tool_list)

    # Verify registry has data
    assert len(registry.tools) > 0
    assert len(registry.available_tools) > 0
    assert len(registry.tools_by_checksum) > 0
    assert registry.last_update != UNIX_EPOCH

    registry.clear_registry()

    # Verify registry is cleared
    assert len(registry.tools) == 0
    assert len(registry.available_tools) == 0
    assert len(registry.tools_by_checksum) == 0
    assert registry.last_update == UNIX_EPOCH


@patch("pan_mcp_relay.tool_registry.logger")
def test_clear_registry_logging(mock_logger):
    """Test that clear registry logs information."""
    registry = ToolRegistry()
    registry.clear_registry()

    mock_logger.info.assert_called_with("Tool registry cleared.")


def test_len_operator(sample_tool_list):
    """Test __len__ operator for registry."""
    registry = ToolRegistry()

    assert len(registry) == 0

    registry.update_registry(sample_tool_list)

    assert len(registry) == 6


def test_contains_operator(echo_tool):
    """Test __contains__ operator for registry."""
    registry = ToolRegistry()

    assert echo_tool.sha256_hash not in registry

    registry.update_registry([echo_tool])

    assert echo_tool.sha256_hash in registry
    assert "nonexistent_hash" not in registry


def test_repr_operator(sample_tool_list):
    """Test __repr__ operator for registry."""
    registry = ToolRegistry()

    with patch("pan_mcp_relay.tool_registry.datetime") as mock_datetime:
        mock_now = datetime(2024, 1, 15, 12, 0, 0)
        mock_datetime.now.return_value = mock_now

        registry.update_registry(sample_tool_list)

        repr_str = repr(registry)

    expected_str = f"ToolRegistry(total_tools=6, available_tools=5, last_updated={mock_now})"
    assert repr_str == expected_str


def test_registry_workflow_integration(sample_tool_list):
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
    echo_tool = next(tool for tool in sample_tool_list if tool.name == "echo_tool")
    found_tool = registry.get_tool_by_hash(echo_tool.sha256_hash)
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


def test_concurrent_updates_scenario(sample_tool_list):
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
        found_tool = registry.get_tool_by_hash(tool.sha256_hash)
        assert found_tool == tool


def test_performance_considerations_large_tool_set():
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
            state=state,
        )
        large_tool_list.append(tool)

    # Update registry
    registry.update_registry(large_tool_list)

    # Verify operations are efficient
    assert len(registry) == 100
    assert len(registry.get_available_tools()) == 50  # Half are enabled

    # Hash lookup should be O(1)
    first_tool = large_tool_list[0]
    found_tool = registry.get_tool_by_hash(first_tool.sha256_hash)
    assert found_tool == first_tool

    # Server mapping should group correctly
    server_map = registry.get_server_tool_map()
    assert len(server_map) == 10  # 10 different servers
    for server_tools in server_map.values():
        assert len(server_tools) == 10  # 10 tools per server


def test_mixed_tool_states_handling():
    """Test registry handling of tools with different states."""
    registry = ToolRegistry()

    # Create tools with different states
    enabled_tool = InternalTool(
        name="enabled_echo_tool",
        description="Enabled echo tool",
        inputSchema={"type": "object"},
        server_name="test-server",
        state=ToolState.ENABLED,
    )

    disabled_tool = InternalTool(
        name="disabled_error_tool",
        description="Disabled error tool",
        inputSchema={"type": "object"},
        server_name="test-server",
        state=ToolState.DISABLED_ERROR,
    )

    tools = [enabled_tool, disabled_tool]
    registry.update_registry(tools)

    # Test filtering
    assert len(registry.get_all_tools()) == 2
    assert len(registry.get_available_tools()) == 1
    assert registry.get_available_tools()[0].state == ToolState.ENABLED

    # Test hash mapping includes all tools regardless of state
    assert len(registry.tools_by_checksum) == 2
    assert enabled_tool.sha256_hash in registry.tools_by_checksum
    assert disabled_tool.sha256_hash in registry.tools_by_checksum


def test_tool_registry_edge_cases():
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
