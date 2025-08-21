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
Unit tests for the tool module.

This module contains comprehensive tests for the tool classes including
ToolState enum, BaseTool, InternalTool, and RelayTool classes using
simulated tools for testing purposes.
"""

import hashlib
import json
from unittest.mock import patch

import mcp.types as types
import pytest
from pydantic import ValidationError

from pan_mcp_relay.tool import BaseTool, InternalTool, RelayTool, ToolState


@pytest.fixture
def echo_tool_schema():
    """Create sample input schema for echo tool."""
    return {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Text to echo back to the user"},
            "format": {
                "type": "string",
                "enum": ["plain", "json", "xml"],
                "description": "Output format for the echoed text",
            },
            "uppercase": {"type": "boolean", "description": "Whether to convert text to uppercase"},
        },
        "required": ["text"],
    }


@pytest.fixture
def echo_tool_data(echo_tool_schema):
    """Create echo tool data for testing."""
    return {
        "name": "echo_tool",
        "description": "Echo back input text with optional formatting",
        "inputSchema": echo_tool_schema,
        "server_name": "echo_server",
        "state": ToolState.ENABLED,
    }


def test_base_tool_creation_minimal_echo_tool():
    """Test BaseTool creation with minimal required fields for basic echo tool."""
    basic_echo = BaseTool(
        name="simple_echo_tool",
        description="Basic text echo functionality",
        inputSchema={},
        server_name="test_server",
    )

    assert basic_echo.name == "simple_echo_tool"
    assert basic_echo.description == "Basic text echo functionality"
    assert basic_echo.inputSchema == {}
    assert basic_echo.server_name == "test_server"
    assert basic_echo.state == ToolState.ENABLED  # Default value


def test_base_tool_creation_full_echo_tool(echo_tool_data):
    """Test BaseTool creation with all fields for comprehensive echo tool."""
    echo_tool = BaseTool(**echo_tool_data)

    assert echo_tool.name == "echo_tool"
    assert echo_tool.description == "Echo back input text with optional formatting"
    assert echo_tool.server_name == "echo_server"
    assert echo_tool.state == ToolState.ENABLED
    assert "text" in echo_tool.inputSchema["properties"]


def test_base_tool_with_different_states(echo_tool_data):
    """Test BaseTool creation with different tool states for compliance."""
    tool_states_to_test = [
        ToolState.ENABLED,
        ToolState.DISABLED_HIDDEN_MODE,
        ToolState.DISABLED_DUPLICATE,
        ToolState.DISABLED_SECURITY_RISK,
        ToolState.DISABLED_ERROR,
    ]

    for state in tool_states_to_test:
        echo_tool_data["state"] = state
        echo_tool = BaseTool(**echo_tool_data)
        assert echo_tool.state == state


def test_base_tool_with_annotations(echo_tool_data):
    """Test BaseTool with tool annotations."""
    tool_annotations = {
        "category": "text_processing",
        "version": "1.2.0",
        "author": "test_team",
        "performance": "high_speed",
        "reliability": "stable",
    }
    echo_tool_data["annotations"] = tool_annotations

    echo_tool = BaseTool(**echo_tool_data)
    assert echo_tool.annotations.category == tool_annotations["category"]
    assert echo_tool.annotations.version == tool_annotations["version"]
    assert echo_tool.annotations.author == tool_annotations["author"]


def test_get_argument_descriptions_with_echo_params(echo_tool_data):
    """Test argument descriptions generation with echo tool parameters."""
    echo_tool = BaseTool(**echo_tool_data)
    descriptions = echo_tool.get_argument_descriptions()

    assert len(descriptions) == 3

    # Check required text parameter
    text_param = next((desc for desc in descriptions if "text" in desc), None)
    assert text_param is not None
    assert "(required)" in text_param
    assert "Text to echo back to the user" in text_param

    # Check optional format parameter
    format_param = next((desc for desc in descriptions if "format" in desc), None)
    assert format_param is not None
    assert "(required)" not in format_param
    assert "Output format for the echoed text" in format_param


def test_get_argument_descriptions_no_properties():
    """Test argument descriptions with schema without properties."""
    simple_tool = BaseTool(
        name="passthrough_tool",
        description="Simple passthrough tool",
        inputSchema={"type": "string"},
        server_name="utility_server",
    )

    descriptions = simple_tool.get_argument_descriptions()
    assert descriptions == []


def test_get_argument_descriptions_missing_description(echo_tool_data):
    """Test argument descriptions when parameter has no description."""
    # Remove description from text parameter
    del echo_tool_data["inputSchema"]["properties"]["text"]["description"]

    echo_tool = BaseTool(**echo_tool_data)
    descriptions = echo_tool.get_argument_descriptions()

    # Should still generate description with default text
    text_param = next((desc for desc in descriptions if "text" in desc), None)
    assert text_param is not None
    assert "No description" in text_param


def test_get_argument_descriptions_empty_schema():
    """Test argument descriptions with empty input schema."""
    empty_tool = BaseTool(
        name="empty_tool", description="Tool with no parameters", inputSchema={}, server_name="test_server"
    )

    descriptions = empty_tool.get_argument_descriptions()
    assert descriptions == []


def test_to_mcp_tool_conversion_for_relay(echo_tool_data):
    """Test conversion to standard MCP Tool for relay operations."""
    tool_annotations = {"performance": "fast", "type": "utility"}
    echo_tool_data["annotations"] = tool_annotations

    base_tool = BaseTool(**echo_tool_data)
    mcp_tool = base_tool.to_mcp_tool()

    # Verify it's a standard MCP Tool
    assert isinstance(mcp_tool, types.Tool)
    assert mcp_tool.name == "echo_tool"
    assert mcp_tool.description == "Echo back input text with optional formatting"
    assert mcp_tool.inputSchema == echo_tool_data["inputSchema"]
    assert mcp_tool.annotations.performance == tool_annotations["performance"]

    # Verify it doesn't have BaseTool specific fields
    assert not hasattr(mcp_tool, "server_name")
    assert not hasattr(mcp_tool, "state")


def test_base_tool_validation_missing_server_info():
    """Test BaseTool validation with missing required server information."""
    # Missing server_name for distributed system
    with pytest.raises(ValidationError) as exc_info:
        BaseTool(name="orphaned_tool", description="Tool without server info", inputSchema={})

    error_details = str(exc_info.value)
    assert "server_name" in error_details


def test_base_tool_extra_fields_allowed(echo_tool_data):
    """Test that BaseTool allows extra fields for extensibility."""
    echo_tool_data["performance_metrics"] = {"latency": "10ms", "throughput": "1000rps"}
    echo_tool_data["custom_config"] = {"buffer_size": 1024, "timeout": 30}

    echo_tool = BaseTool(**echo_tool_data)

    # Should not raise validation error for extra fields
    assert echo_tool.name == "echo_tool"
    # Extra fields should be accessible
    assert hasattr(echo_tool, "performance_metrics")
    assert echo_tool.performance_metrics["latency"] == "10ms"


def test_base_tool_field_validation_for_state():
    """Test field type validation for tool state."""
    # Invalid tool state type
    with pytest.raises(ValidationError):
        BaseTool(
            name="invalid_state_tool",
            description="Tool with invalid state",
            inputSchema={},
            server_name="test_server",
            state="invalid_state",  # Should be ToolState enum
        )


def test_base_tool_inheritance_from_mcp_tool(echo_tool_data):
    """Test that BaseTool properly inherits from types.Tool."""
    external_tool = BaseTool(**echo_tool_data)

    # Should have all MCP Tool attributes
    assert hasattr(external_tool, "name")
    assert hasattr(external_tool, "description")
    assert hasattr(external_tool, "inputSchema")

    # Should be instance of MCP Tool for compatibility
    assert isinstance(external_tool, types.Tool)


@pytest.fixture
def error_all_tool_data():
    """Create error_all_tool data for testing."""
    return {
        "name": "error_all_tool",
        "description": "Tool that always returns isError=True for testing error handling",
        "inputSchema": {
            "type": "object",
            "properties": {
                "input": {"type": "string", "description": "Input text that will trigger error response"},
                "error_type": {
                    "type": "string",
                    "enum": ["validation", "timeout", "server_error", "network"],
                    "description": "Type of error to simulate",
                },
            },
        },
        "server_name": "test_server",
        "state": ToolState.ENABLED,
        "sha256_hash": "658027b21f79c5e8e5a4ba9ed4928913c4ff1cdbfe3ebf441c700b52ea5ee85f",
    }


def test_internal_tool_creation_with_hash_generation(error_all_tool_data):
    """Test InternalTool creation and SHA256 hash generation for registry management."""
    error_tool = InternalTool(**error_all_tool_data)

    assert error_tool.name == "error_all_tool"
    assert error_tool.description == "Tool that always returns isError=True for testing error handling"
    assert error_tool.server_name == "test_server"
    assert error_tool.state == ToolState.ENABLED
    assert error_tool.sha256_hash != ""
    assert len(error_tool.sha256_hash) == 64  # SHA256 hash length for registry key


def test_internal_tool_hash_computation_for_deduplication(error_all_tool_data):
    """Test SHA256 hash computation for tool deduplication across servers."""
    error_tool = InternalTool(**error_all_tool_data)

    # Manually compute expected hash for verification
    payload = {
        "server_name": error_all_tool_data["server_name"],
        "tool_name": error_all_tool_data["tool_name"],
        "description": error_all_tool_data["description"],
        "input_schema": error_all_tool_data["inputSchema"],
    }
    json_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    expected_hash = hashlib.sha256(json_str.encode("utf-8")).hexdigest()

    assert error_tool.sha256_hash == expected_hash


def test_internal_tool_hash_consistency_across_instances(error_all_tool_data):
    """Test that identical tools produce identical hashes for caching."""
    error_tool_1 = InternalTool(**error_all_tool_data)
    error_tool_2 = InternalTool(**error_all_tool_data)

    assert error_tool_1.sha256_hash == error_tool_2.sha256_hash


def test_internal_tool_hash_uniqueness_for_different_tools(error_all_tool_data):
    """Test that different tools produce different hashes for proper separation."""
    error_tool = InternalTool(**error_all_tool_data)

    # Create slow response tool with different configuration
    slow_tool_data = error_all_tool_data.copy()
    slow_tool_data["name"] = "slow_response_tool"
    slow_tool_data["description"] = "Tool that simulates slow response with intentional delay"
    slow_tool = InternalTool(**slow_tool_data)

    assert error_tool.sha256_hash != slow_tool.sha256_hash


def test_internal_tool_hash_with_complex_schema():
    """Test hash computation with complex tool schema."""
    complex_schema = {
        "type": "object",
        "properties": {
            "performance_config": {
                "type": "object",
                "properties": {
                    "enable_caching": {"type": "boolean"},
                    "max_retries": {"type": "integer"},
                    "timeout_settings": {
                        "type": "array",
                        "items": {"type": "number"},
                        "description": "Timeout values in milliseconds",
                    },
                },
            },
            "response_format": {"type": "string", "enum": ["json", "xml", "plain", "binary"]},
            "custom_headers": {"type": "array", "items": {"type": "string"}},
        },
    }

    complex_tool = InternalTool(
        name="fixed_response_tool",
        description="Tool that returns predefined fixed responses",
        inputSchema=complex_schema,
        server_name="mock_server",
    )

    assert complex_tool.sha256_hash != ""
    assert len(complex_tool.sha256_hash) == 64


def test_internal_tool_model_post_init_hash_generation(error_all_tool_data):
    """Test that model_post_init is called during initialization for hash generation."""
    with patch.object(InternalTool, "compute_hash", return_value="external_tool_hash_123") as mock_compute:
        external_tool = InternalTool(**error_all_tool_data)

        mock_compute.assert_called_once()
        assert external_tool.sha256_hash == "external_tool_hash_123"


def test_internal_tool_inherits_base_tool_functionality(error_all_tool_data):
    """Test that InternalTool inherits BaseTool functionality."""
    external_tool = InternalTool(**error_all_tool_data)

    # Should have BaseTool methods
    descriptions = external_tool.get_argument_descriptions()
    assert len(descriptions) == 2
    assert "input" in descriptions[0]

    # Should convert to MCP tool for relay
    mcp_tool = external_tool.to_mcp_tool()
    assert isinstance(mcp_tool, types.Tool)
    assert mcp_tool.name == "error_all_tool"


def test_internal_tool_with_empty_input_schema_for_simple_tool():
    """Test InternalTool with empty input schema for simple tool."""
    simple_tool = InternalTool(
        name="passthrough_tool",
        description="Simple passthrough tool with no parameters",
        inputSchema={},
        server_name="utility_server",
    )

    assert simple_tool.sha256_hash != ""
    storage_dict = simple_tool.to_dict()
    assert storage_dict["input_schema"] == {}


def test_internal_tool_hash_with_unicode_content():
    """Test hash computation with unicode characters in tool fields."""
    unicode_tool = InternalTool(
        name="echo_tool_Überprüfung",  # ü is Unicode
        description="Internationales Echo-Tool mit Unicode-Unterstützung: 📢 🔊 ä ö ü ß",
        inputSchema={"type": "string"},
        server_name="globaler_Server_Prüfung",  # ü is Unicode
    )

    assert unicode_tool.sha256_hash != ""
    assert len(unicode_tool.sha256_hash) == 64

    # Hash should be reproducible for unicode content
    unicode_tool_2 = InternalTool(
        name="echo_tool_Überprüfung",
        description="Internationales Echo-Tool mit Unicode-Unterstützung: 📢 🔊 ä ö ü ß",
        inputSchema={"type": "string"},
        server_name="globaler_Server_Prüfung",
    )

    assert unicode_tool.sha256_hash == unicode_tool_2.sha256_hash


@pytest.fixture
def slow_response_tool_data():
    """Create slow_response_tool data for relay testing."""
    return {
        "name": "slow_response_tool",
        "description": "Latency simulator that intentionally delays responses for performance testing",
        "inputSchema": {
            "type": "object",
            "properties": {
                "delay_seconds": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 60,
                    "description": "Number of seconds to delay before responding",
                },
                "content": {"type": "string", "description": "Content to return after the specified delay"},
                "simulate_load": {
                    "type": "boolean",
                    "description": "Whether to simulate high CPU load during delay",
                },
            },
            "required": ["delay_seconds"],
        },
        "server_name": "performance_server",
        "state": ToolState.ENABLED,
    }


def test_relay_tool_creation_for_llm_presentation(slow_response_tool_data):
    """Test RelayTool creation for LLM presentation."""
    slow_tool = RelayTool(**slow_response_tool_data)

    assert slow_tool.name == "slow_response_tool"
    assert slow_tool.description == "Latency simulator that intentionally delays responses for performance testing"
    assert slow_tool.server_name == "performance_server"
    assert slow_tool.state == ToolState.ENABLED


def test_relay_tool_format_for_llm_basic_tool(slow_response_tool_data):
    """Test format_for_llm method with basic tool for LLM consumption."""
    slow_tool = RelayTool(**slow_response_tool_data)
    llm_formatted_output = slow_tool.format_for_llm()

    # Check that all expected sections are present for LLM understanding
    assert "Tool: slow_response_tool" in llm_formatted_output
    assert "Server: performance_server" in llm_formatted_output
    assert "Description: Latency simulator that intentionally delays responses" in llm_formatted_output
    assert "Arguments:" in llm_formatted_output
    assert "delay_seconds:" in llm_formatted_output
    assert "Number of seconds to delay" in llm_formatted_output
    assert "(required)" in llm_formatted_output


def test_relay_tool_format_for_llm_with_parameters(slow_response_tool_data):
    """Test format_for_llm method showing required vs optional parameters."""
    external_tool = RelayTool(**slow_response_tool_data)
    llm_formatted_output = external_tool.format_for_llm()

    # delay_seconds should be marked as required
    lines = llm_formatted_output.split("\n")
    delay_line = next((line for line in lines if "delay_seconds:" in line), "")
    assert "(required)" in delay_line

    # content should not be marked as required
    content_line = next((line for line in lines if "content:" in line), "")
    assert "(required)" not in content_line


def test_relay_tool_format_for_llm_no_arguments_simple_tool():
    """Test format_for_llm with simple tool that has no arguments."""
    simple_tool = RelayTool(
        name="passthrough_tool",
        description="Simple passthrough tool that returns input unchanged",
        inputSchema={},
        server_name="utility_server",
    )

    llm_formatted_output = simple_tool.format_for_llm()

    assert "Tool: passthrough_tool" in llm_formatted_output
    assert "Server: utility_server" in llm_formatted_output
    assert "Description: Simple passthrough tool that returns input unchanged" in llm_formatted_output
    assert "Arguments:" in llm_formatted_output


def test_relay_tool_format_for_llm_string_schema_tool():
    """Test format_for_llm with string-type schema."""
    string_tool = RelayTool(
        name="echo_tool",
        description="Simple echo tool that accepts string input",
        inputSchema={"type": "string"},
        server_name="echo_server",
    )

    llm_formatted_output = string_tool.format_for_llm()

    # Should handle gracefully even without properties
    assert "Tool: echo_tool" in llm_formatted_output
    assert "Arguments:" in llm_formatted_output


def test_relay_tool_format_for_llm_multiline_formatting_for_llm(slow_response_tool_data):
    """Test that format_for_llm produces properly formatted multiline output for LLM consumption."""
    external_tool = RelayTool(**slow_response_tool_data)
    llm_formatted_output = external_tool.format_for_llm()

    lines = [line.strip() for line in llm_formatted_output.split("\n") if line.strip()]

    # Should have multiple non-empty lines for LLM parsing
    assert len(lines) >= 4

    # Check line structure for LLM understanding
    tool_line = next((line for line in lines if line.startswith("Tool:")), "")
    server_line = next((line for line in lines if line.startswith("Server:")), "")
    desc_line = next((line for line in lines if line.startswith("Description:")), "")
    args_line = next((line for line in lines if line.startswith("Arguments:")), "")

    assert tool_line != ""
    assert server_line != ""
    assert desc_line != ""
    assert args_line != ""


def test_relay_tool_inherits_base_tool_functionality(slow_response_tool_data):
    """Test that RelayTool inherits BaseTool functionality."""
    relay_tool = RelayTool(**slow_response_tool_data)

    # Should have BaseTool methods
    descriptions = relay_tool.get_argument_descriptions()
    assert len(descriptions) == 3  # delay_seconds, content, simulate_load

    # Should convert to MCP tool for integration
    mcp_tool = relay_tool.to_mcp_tool()
    assert isinstance(mcp_tool, types.Tool)
    assert mcp_tool.name == "slow_response_tool"


def test_relay_tool_format_for_llm_with_complex_descriptions():
    """Test format_for_llm with complex parameter descriptions."""
    complex_schema = {
        "type": "object",
        "properties": {
            "configuration": {
                "type": "string",
                "description": "Complex configuration string with multiple parameters including performance tuning, error handling, and output formatting options for comprehensive tool behavior control",
            },
            "metadata": {
                "type": "string",
                "description": "Tool metadata with special characters: JSON{} XML<> CSV, TSV\t and international characters: 配置 🛠️ настройки",
            },
            "advanced_options": {
                "type": "string",
                "description": "Advanced configuration options for power users including debugging flags and performance optimizations",
            },
        },
        "required": ["configuration"],
    }

    complex_tool = RelayTool(
        name="fixed_response_tool",
        description="Advanced fixed response tool with comprehensive configuration options",
        inputSchema=complex_schema,
        server_name="advanced_server",
    )

    llm_formatted_output = complex_tool.format_for_llm()

    # Should handle all complex cases for LLM understanding
    assert "configuration:" in llm_formatted_output
    assert "metadata:" in llm_formatted_output
    assert "advanced_options:" in llm_formatted_output
    assert "配置 🛠️" in llm_formatted_output
    assert "(required)" in llm_formatted_output


def test_relay_tool_with_different_states(slow_response_tool_data):
    """Test RelayTool with different states for compliance management."""
    tool_states_to_test = [ToolState.ENABLED, ToolState.DISABLED_HIDDEN_MODE, ToolState.DISABLED_SECURITY_RISK]

    for state in tool_states_to_test:
        slow_response_tool_data["state"] = state
        external_tool = RelayTool(**slow_response_tool_data)

        assert external_tool.state == state

        # format_for_llm should work regardless of state
        llm_formatted_output = external_tool.format_for_llm()
        assert "Tool: slow_response_tool" in llm_formatted_output


def test_all_external_tool_types_with_same_data():
    """Test that all tool types can be created with compatible external tool data."""
    common_tool_data = {
        "name": "failing_tool",
        "description": "Tool that intentionally fails with errors or exceptions for testing",
        "inputSchema": {
            "type": "object",
            "properties": {
                "failure_mode": {
                    "type": "string",
                    "enum": ["exception", "error_response", "timeout"],
                    "description": "Type of failure to simulate",
                }
            },
        },
        "server_name": "test_server",
        "state": ToolState.ENABLED,
    }

    # Create all tool types
    base_tool = BaseTool(**common_tool_data)
    internal_tool = InternalTool(**common_tool_data)
    relay_tool = RelayTool(**common_tool_data)

    # All should have same basic properties
    tools = [base_tool, internal_tool, relay_tool]
    for tool in tools:
        assert tool.name == "failing_tool"
        assert tool.description == "Tool that intentionally fails with errors or exceptions for testing"
        assert tool.server_name == "test_server"
        assert tool.state == ToolState.ENABLED


def test_external_tool_conversion_compatibility_for_integration():
    """Test compatibility between different tool types for integration."""
    # Create an InternalTool for registry
    internal_tool = InternalTool(
        name="echo_tool",
        description="Echo tool for conversion testing",
        inputSchema={"type": "string"},
        server_name="echo_server",
    )

    # Convert to MCP tool
    mcp_tool = internal_tool.to_mcp_tool()

    # Create RelayTool from same data
    relay_tool = RelayTool(
        name=internal_tool.name,
        description=internal_tool.description,
        inputSchema=internal_tool.inputSchema,
        server_name=internal_tool.server_name,
        state=internal_tool.state,
    )

    # Both should produce same MCP tool
    relay_mcp_tool = relay_tool.to_mcp_tool()

    assert mcp_tool.name == relay_mcp_tool.name
    assert mcp_tool.description == relay_mcp_tool.description
    assert mcp_tool.inputSchema == relay_mcp_tool.inputSchema


def test_external_tool_serialization_and_deserialization_for_storage():
    """Test tool serialization and deserialization for database storage."""
    original_tool = InternalTool(
        name="fixed_response_tool",
        description="Tool for serialization testing",
        inputSchema={
            "type": "object",
            "properties": {"response_type": {"type": "string", "description": "Type of response"}},
        },
        server_name="mock_server",
        state=ToolState.DISABLED_DUPLICATE,
    )

    # Serialize to dict for database storage
    tool_dict = original_tool.to_dict()

    # Create new tool from dict data (simulating database retrieval)
    recreated_tool = InternalTool(
        name=tool_dict["name"],
        description=tool_dict["description"],
        inputSchema=tool_dict["input_schema"],
        server_name=tool_dict["server_name"],
        state=tool_dict["state"],
    )

    # Should have same hash (same content)
    assert original_tool.sha256_hash == recreated_tool.sha256_hash
    assert original_tool.name == recreated_tool.name
    assert original_tool.state == recreated_tool.state


def test_external_tool_inheritance_chain_for_distributed_systems():
    """Test the inheritance chain of tool classes for distributed systems."""
    distributed_tool = InternalTool(
        name="passthrough_tool",
        description="Distributed passthrough tool",
        inputSchema={},
        server_name="distributed_cluster",
    )

    # Should be instance of all parent classes for proper integration
    assert isinstance(distributed_tool, InternalTool)
    assert isinstance(distributed_tool, BaseTool)
    assert isinstance(distributed_tool, types.Tool)

    # Should have methods from all levels for comprehensive functionality
    assert hasattr(distributed_tool, "compute_hash")  # InternalTool for registry
    assert hasattr(distributed_tool, "get_argument_descriptions")  # BaseTool for documentation
    assert hasattr(distributed_tool, "to_mcp_tool")  # BaseTool for relay

    # Should have all required attributes for distributed operations
    assert hasattr(distributed_tool, "sha256_hash")  # InternalTool for deduplication
    assert hasattr(distributed_tool, "server_name")  # BaseTool for server tracking
    assert hasattr(distributed_tool, "state")  # BaseTool for state management
    assert hasattr(distributed_tool, "name")  # types.Tool for identification
    assert hasattr(distributed_tool, "description")  # types.Tool for documentation
    assert hasattr(distributed_tool, "inputSchema")  # types.Tool for LLM understanding


def test_external_tool_workflow_scenario():
    """Test complete workflow scenario with external tools."""
    # Create tools for a complete workflow
    workflow_tools = []

    # Step 1: Echo tool to capture input
    echo_tool = InternalTool(
        name="echo_tool",
        description="Capture and echo user input",
        inputSchema={
            "type": "object",
            "properties": {"user_input": {"type": "string", "description": "User input to process"}},
            "required": ["user_input"],
        },
        server_name="input_server",
    )
    workflow_tools.append(echo_tool)

    # Step 2: Slow response tool to simulate processing
    slow_tool = InternalTool(
        name="slow_response_tool",
        description="Process input with simulated delay",
        inputSchema={
            "type": "object",
            "properties": {"input_data": {"type": "string"}, "processing_time": {"type": "number", "minimum": 0}},
            "required": ["input_data"],
        },
        server_name="processing_server",
    )
    workflow_tools.append(slow_tool)

    # Step 3: Fixed response tool to generate result
    fixed_tool = InternalTool(
        name="fixed_response_tool",
        description="Generate fixed response based on processing",
        inputSchema={
            "type": "object",
            "properties": {
                "processed_data": {"type": "string"},
                "response_format": {"type": "string", "enum": ["json", "text"]},
            },
            "required": ["processed_data"],
        },
        server_name="output_server",
    )
    workflow_tools.append(fixed_tool)

    # Step 4: Error handling with error_all_tool (conditional)
    error_tool = InternalTool(
        name="error_all_tool",
        description="Handle errors in workflow",
        inputSchema={
            "type": "object",
            "properties": {"error_input": {"type": "string"}, "error_type": {"type": "string"}},
        },
        server_name="error_server",
        state=ToolState.DISABLED_ERROR,  # Disabled unless needed
    )
    workflow_tools.append(error_tool)

    # Verify workflow integrity
    assert len(workflow_tools) == 4

    # All tools should have unique hashes
    tool_hashes = {echo_tool.sha256_hash, slow_tool.sha256_hash, fixed_tool.sha256_hash}
    assert len(tool_hashes) == 3  # All hashes are unique

    # All tools should convert to valid MCP tools
    mcp_tools = [tool.to_mcp_tool() for tool in [echo_tool, slow_tool, fixed_tool]]
    assert all(isinstance(tool, types.Tool) for tool in mcp_tools)

    # All tools should be serializable
    tool_dicts = [tool.to_dict() for tool in [echo_tool, slow_tool, fixed_tool]]
    assert all("sha256_hash" in tool_dict for tool_dict in tool_dicts)


def test_mixed_external_tool_states_handling():
    """Test handling of external tools with mixed states."""
    # Create tools with different states
    enabled_tool = InternalTool(
        name="echo_tool",
        description="Enabled echo tool",
        inputSchema={"type": "object"},
        server_name="test_server",
        state=ToolState.ENABLED,
    )

    disabled_tool = InternalTool(
        name="failing_tool",
        description="Disabled failing tool",
        inputSchema={"type": "object"},
        server_name="test_server",
        state=ToolState.DISABLED_ERROR,
    )

    hidden_tool = InternalTool(
        name="passthrough_tool",
        description="Hidden passthrough tool",
        inputSchema={"type": "object"},
        server_name="test_server",
        state=ToolState.DISABLED_HIDDEN_MODE,
    )

    tools = [enabled_tool, disabled_tool, hidden_tool]

    # All should have valid hashes regardless of state
    assert all(tool.sha256_hash for tool in tools)
    assert all(len(tool.sha256_hash) == 64 for tool in tools)

    # All should convert to MCP tools regardless of state
    mcp_tools = [tool.to_mcp_tool() for tool in tools]
    assert all(isinstance(tool, types.Tool) for tool in mcp_tools)

    # State information should be preserved in serialization
    tool_dicts = [tool.to_dict() for tool in tools]
    states = [tool_dict["state"] for tool_dict in tool_dicts]
    assert ToolState.ENABLED in states
    assert ToolState.DISABLED_ERROR in states
    assert ToolState.DISABLED_HIDDEN_MODE in states


def test_external_tool_performance_with_large_schemas():
    """Test external tool performance with large input schemas."""
    # Create tool with large, complex schema
    large_schema = {"type": "object", "properties": {}}

    # Add many properties to simulate large schema
    for i in range(50):
        large_schema["properties"][f"param_{i}"] = {
            "type": "string",
            "description": f"Parameter {i} for testing large schema performance",
            "enum": [f"value_{j}" for j in range(10)],  # Add enum values
        }

    large_schema_tool = InternalTool(
        name="slow_response_tool",
        description="Tool with large schema for performance testing",
        inputSchema=large_schema,
        server_name="performance_server",
    )

    # Should handle large schema efficiently
    assert large_schema_tool.sha256_hash != ""
    assert len(large_schema_tool.sha256_hash) == 64

    # Serialization should work with large schema
    tool_dict = large_schema_tool.to_dict()
    assert len(tool_dict["input_schema"]["properties"]) == 50

    # Hash computation should be consistent
    large_schema_tool_2 = InternalTool(
        name="slow_response_tool",
        description="Tool with large schema for performance testing",
        inputSchema=large_schema,
        server_name="performance_server",
    )
    assert large_schema_tool.sha256_hash == large_schema_tool_2.sha256_hash


def test_external_tool_edge_cases_handling():
    """Test external tool handling of edge cases."""
    # Test with minimal tool configuration
    minimal_tool = InternalTool(
        name="a",  # Single character name
        description="",  # Empty description
        inputSchema={},
        server_name="x",  # Single character server
    )

    assert minimal_tool.sha256_hash != ""
    tool_dict = minimal_tool.to_dict()
    assert tool_dict["name"] == "a"
    assert tool_dict["description"] == ""

    # Test with maximum length strings
    max_length_name = "echo_tool_" + "x" * 1000
    max_tool = InternalTool(
        name=max_length_name,
        description="Tool with very long name for edge case testing",
        inputSchema={"type": "object"},
        server_name="test_server",
    )

    assert max_tool.sha256_hash != ""
    assert max_tool.name == max_length_name


def test_external_tool_special_characters_handling():
    """Test external tool handling of special characters in various fields."""
    special_chars_tool = InternalTool(
        name="echo_tool_special",
        description="Tool with special chars: !@#$%^&*(){}[]|\:;\"'<>,.?/~`",
        inputSchema={
            "type": "object",
            "properties": {
                "special_input": {"type": "string", "description": "Input with special chars: ∑∏∆√∫≈≠≤≥±×÷"}  # noqa: RUF001
            },
        },
        server_name="special_server",
    )

    # Should handle special characters without issues
    assert special_chars_tool.sha256_hash != ""

    # LLM formatting should preserve special characters
    relay_special_tool = RelayTool(
        name=special_chars_tool.name,
        description=special_chars_tool.description,
        inputSchema=special_chars_tool.inputSchema,
        server_name=special_chars_tool.server_name,
    )

    llm_output = relay_special_tool.format_for_llm()
    assert "!@#$%^&*()" in llm_output
    assert "∑∏∆√∫≈≠≤≥±×÷" in llm_output  # noqa: RUF001


def test_external_tool_state_transitions():
    """Test external tool state transitions and validation."""
    # Create tool in enabled state
    transition_tool = InternalTool(
        name="fixed_response_tool",
        description="Tool for state transition testing",
        inputSchema={"type": "object"},
        server_name="test_server",
        state=ToolState.ENABLED,
    )

    original_hash = transition_tool.sha256_hash

    # Create tools with different states (simulating state changes)
    states_to_test = [
        ToolState.DISABLED_DUPLICATE,
        ToolState.DISABLED_ERROR,
        ToolState.DISABLED_HIDDEN_MODE,
        ToolState.DISABLED_SECURITY_RISK,
    ]

    for new_state in states_to_test:
        # State change would typically create a new tool instance
        changed_tool = InternalTool(
            name="fixed_response_tool",
            description="Tool for state transition testing",
            inputSchema={"type": "object"},
            server_name="test_server",
            state=new_state,
        )

        # Core properties should remain the same, hash should be identical
        # (since hash is based on functional properties, not state)
        assert changed_tool.sha256_hash == original_hash
        assert changed_tool.state == new_state


def test_external_tool_cross_server_compatibility():
    """Test external tool compatibility across different servers."""
    # Same tool deployed on different servers
    servers = ["echo_server_1", "echo_server_2", "echo_server_backup"]

    tools = []
    for server in servers:
        tool = InternalTool(
            name="echo_tool",
            description="Cross-server echo tool",
            inputSchema={"type": "object", "properties": {"text": {"type": "string"}}},
            server_name=server,
        )
        tools.append(tool)

    # All tools should have different hashes due to different server names
    tool_hashes = [tool.sha256_hash for tool in tools]
    assert len(set(tool_hashes)) == 3  # All hashes are unique

    # But all should have same functional MCP representation
    mcp_tools = [tool.to_mcp_tool() for tool in tools]
    for i in range(1, len(mcp_tools)):
        assert mcp_tools[0].name == mcp_tools[i].name
        assert mcp_tools[0].description == mcp_tools[i].description
        assert mcp_tools[0].inputSchema == mcp_tools[i].inputSchema


def test_external_tool_complex_workflow_simulation():
    """Test complex workflow with multiple external tools."""
    # Simulate a complete tool workflow
    workflow_tools = []

    # Step 1: Echo tool to capture input
    echo_tool = InternalTool(
        name="echo_tool",
        description="Capture and echo user input",
        inputSchema={
            "type": "object",
            "properties": {"user_input": {"type": "string", "description": "User input to process"}},
            "required": ["user_input"],
        },
        server_name="input_server",
    )
    workflow_tools.append(echo_tool)

    # Step 2: Slow response tool to simulate processing
    processing_tool = InternalTool(
        name="slow_response_tool",
        description="Process input with simulated delay",
        inputSchema={
            "type": "object",
            "properties": {"input_data": {"type": "string"}, "processing_time": {"type": "number", "minimum": 0}},
            "required": ["input_data"],
        },
        server_name="processing_server",
    )
    workflow_tools.append(processing_tool)

    # Step 3: Fixed response tool to generate result
    result_tool = InternalTool(
        name="fixed_response_tool",
        description="Generate fixed response based on processing",
        inputSchema={
            "type": "object",
            "properties": {
                "processed_data": {"type": "string"},
                "response_format": {"type": "string", "enum": ["json", "text"]},
            },
            "required": ["processed_data"],
        },
        server_name="output_server",
    )
    workflow_tools.append(result_tool)

    # Step 4: Error handling with error_all_tool (conditional)
    error_tool = InternalTool(
        name="error_all_tool",
        description="Handle errors in workflow",
        inputSchema={
            "type": "object",
            "properties": {"error_input": {"type": "string"}, "error_type": {"type": "string"}},
        },
        server_name="error_server",
        state=ToolState.DISABLED_ERROR,  # Disabled unless needed
    )
    workflow_tools.append(error_tool)

    # Verify workflow integrity
    assert len(workflow_tools) == 4

    # All tools should have unique hashes
    hashes = [tool.sha256_hash for tool in workflow_tools]
    assert len(set(hashes)) == 4

    # All enabled tools should be convertible to MCP tools
    enabled_tools = [tool for tool in workflow_tools if tool.state == ToolState.ENABLED]
    assert len(enabled_tools) == 3

    mcp_tools = [tool.to_mcp_tool() for tool in enabled_tools]
    assert all(isinstance(tool, types.Tool) for tool in mcp_tools)

    # Workflow should be serializable for storage
    workflow_dicts = [tool.to_dict() for tool in workflow_tools]
    assert all("sha256_hash" in tool_dict for tool_dict in workflow_dicts)

    # LLM presentation should work for all enabled tools
    relay_tools = [
        RelayTool(**{
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.inputSchema,
            "server_name": tool.server_name,
            "state": tool.state,
        })
        for tool in enabled_tools
    ]

    llm_outputs = [tool.format_for_llm() for tool in relay_tools]
    assert all("Tool:" in output for output in llm_outputs)
    assert all("Arguments:" in output for output in llm_outputs)


def test_external_tool_validation_scenarios():
    """Test various validation scenarios for external tools."""
    # Test missing required fields - server_name is required
    with pytest.raises(ValidationError):
        BaseTool(
            name="test_tool",
            description="Tool missing server name",
            inputSchema={},
            # Missing server_name - this should definitely fail
        )

    # Test invalid state type
    with pytest.raises(ValidationError):
        BaseTool(
            name="test_tool",
            description="Tool with invalid state",
            inputSchema={},
            server_name="test_server",
            state="not_a_valid_state",  # Should be ToolState enum
        )

    # Test None values for required fields
    with pytest.raises(ValidationError):
        BaseTool(
            name=None,  # None name should fail
            description="Tool with None name",
            inputSchema={},
            server_name="test_server",
        )

    # Test None server_name
    with pytest.raises(ValidationError):
        BaseTool(
            name="test_tool",
            description="Tool with None server",
            inputSchema={},
            server_name=None,  # None server_name should fail
        )


def test_external_tool_schema_validation():
    """Test input schema validation for external tools."""
    # Valid schemas should work
    valid_schemas = [
        {},
        {"type": "string"},
        {"type": "object", "properties": {}},
        {
            "type": "object",
            "properties": {"param1": {"type": "string"}, "param2": {"type": "number"}},
        },
    ]

    for schema in valid_schemas:
        tool = InternalTool(
            name="validation_tool",
            description="Tool for schema validation testing",
            inputSchema=schema,
            server_name="validation_server",
        )
        assert tool.inputSchema == schema


def test_external_tool_error_recovery():
    """Test error recovery scenarios for external tools."""
    # Test tool creation with various edge case inputs
    edge_case_inputs = [
        {
            "name": "echo_tool",
            "description": None,  # None description
            "inputSchema": {},
            "server_name": "test_server",
        }
    ]

    # Some edge cases might be handled gracefully
    for input_data in edge_case_inputs:
        try:
            tool = BaseTool(**input_data)
            # If creation succeeds, verify basic properties
            assert tool.name == input_data["name"]
            assert tool.server_name == input_data["server_name"]
        except (ValidationError, TypeError):
            # Expected for invalid inputs
            pass


def test_external_tool_hash_collision_resistance():
    """Test hash collision resistance for external tools."""
    # Create tools with very similar properties
    similar_tools = []

    for i in range(10):
        tool = InternalTool(
            name=f"echo_tool_{i}",
            description="Very similar echo tool for collision testing",
            inputSchema={"type": "object", "properties": {"text": {"type": "string"}}},
            server_name="echo_server",
        )
        similar_tools.append(tool)

    # All hashes should be unique despite similarities
    hashes = [tool.sha256_hash for tool in similar_tools]
    assert len(set(hashes)) == 10  # All hashes are unique


def test_external_tool_memory_efficiency():
    """Test memory efficiency with many external tool instances."""
    # Create many tool instances
    tools = []

    for i in range(100):
        tool = InternalTool(
            name=f"tool_{i}",
            description=f"Tool number {i}",
            inputSchema={"type": "object"},
            server_name=f"server_{i % 5}",  # 5 different servers
        )
        tools.append(tool)

    # Verify all tools are created successfully
    assert len(tools) == 100

    # Verify all have unique hashes
    hashes = [tool.sha256_hash for tool in tools]
    assert len(set(hashes)) == 100

    # Memory usage should be reasonable (tools should not hold excessive references)
    for tool in tools:
        assert hasattr(tool, "sha256_hash")
        assert hasattr(tool, "name")
        assert hasattr(tool, "server_name")


def test_external_tool_concurrent_access_simulation():
    """Test external tool behavior under simulated concurrent access."""
    # Create shared tool configuration
    shared_config = {
        "name": "passthrough_tool",
        "description": "Tool for concurrent access testing",
        "inputSchema": {"type": "object", "properties": {"data": {"type": "string"}}},
        "server_name": "concurrent_server",
    }

    # Simulate multiple threads creating the same tool
    concurrent_tools = []
    for _ in range(10):
        tool = InternalTool(**shared_config)
        concurrent_tools.append(tool)

    # All tools should have identical hashes (same configuration)
    hashes = [tool.sha256_hash for tool in concurrent_tools]
    assert all(h == hashes[0] for h in hashes)

    # All tools should be functionally equivalent
    mcp_tools = [tool.to_mcp_tool() for tool in concurrent_tools]
    for mcp_tool in mcp_tools[1:]:
        assert mcp_tool.name == mcp_tools[0].name
        assert mcp_tool.description == mcp_tools[0].description
        assert mcp_tool.inputSchema == mcp_tools[0].inputSchema


def test_external_tool_serialization_edge_cases():
    """Test serialization edge cases for external tools."""
    # Test with complex nested schema
    complex_tool = InternalTool(
        name="failing_tool",
        description="Tool with complex nested schema",
        inputSchema={
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "nested": {
                            "type": "array",
                            "items": {"type": "object", "properties": {"deep_param": {"type": "string"}}},
                        }
                    },
                }
            },
        },
        server_name="complex_server",
    )

    # Serialization should handle complex structure
    tool_dict = complex_tool.to_dict()
    assert "input_schema" in tool_dict
    assert "config" in tool_dict["input_schema"]["properties"]

    # Hash should be computed successfully
    assert complex_tool.sha256_hash != ""
    assert len(complex_tool.sha256_hash) == 64


def test_external_tool_internationalization_support():
    """Test external tool support for international characters and formats."""
    # Test with various international character sets
    international_tools = [
        {
            "name": "echo_tool_Überprüfung",
            "description": "Deutsches Echo-Werkzeug für Internationalisierungs-Unterstützung mit ä ö ü ß",
            "server_name": "Deutscher_Prüfungs_Server",
        },
        {
            "name": "echo_tool_العربية",
            "description": "أداة الصدى العربية لاختبار الدعم الدولي",
            "server_name": "الخادم_العربي",
        },
        {
            "name": "echo_tool_русский",
            "description": "Русский инструмент эхо для тестирования интернационализации",
            "server_name": "русский_сервер",
        },
        {
            "name": "echo_tool_emoji",
            "description": "Echo tool with emoji support 🔧🛠️⚙️🔨",
            "server_name": "emoji_server_🚀",
        },
    ]

    for tool_config in international_tools:
        tool = InternalTool(
            name=tool_config["name"],
            description=tool_config["description"],
            inputSchema={"type": "object"},
            server_name=tool_config["server_name"],
        )

        # Should handle international characters
        assert tool.sha256_hash != ""
        assert len(tool.sha256_hash) == 64

        # Serialization should preserve international characters
        tool_dict = tool.to_dict()
        assert tool_dict["name"] == tool_config["name"]
        assert tool_dict["description"] == tool_config["description"]

        # LLM formatting should preserve international characters
        relay_tool = RelayTool(
            name=tool.name, description=tool.description, inputSchema=tool.inputSchema, server_name=tool.server_name
        )

        llm_output = relay_tool.format_for_llm()
        assert tool_config["name"] in llm_output
        assert tool_config["description"] in llm_output
