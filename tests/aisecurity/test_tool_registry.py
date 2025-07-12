"""
Unit tests for the tool module in AI Security MCP Relay.

This module contains comprehensive tests for the tool classes including
ToolState enum, BaseTool, InternalTool, and RelayTool classes used in
AI security MCP relay operations for Palo Alto Networks AI Runtime Security (AIRS).
"""

import pytest
import json
import hashlib
from unittest.mock import MagicMock, patch

import mcp.types as types
from pydantic import ValidationError

from pan_aisecurity_mcp.mcp_relay.tool import (
    ToolState,
    BaseTool,
    InternalTool,
    RelayTool
)


class TestToolState:
    """Test suite for ToolState enum used in AI security scanning tools."""

    def test_tool_state_values_for_security_compliance(self):
        """Test that ToolState enum has correct security-related values for AIRS compliance."""
        assert ToolState.ENABLED == "enabled"
        assert ToolState.DISABLED_HIDDEN_MODE == "disabled - hidden_mode"
        assert ToolState.DISABLED_DUPLICATE == "disabled - duplicate"
        assert ToolState.DISABLED_SECURITY_RISK == "disabled - security risk"
        assert ToolState.DISABLED_ERROR == "disabled - error"

    def test_tool_state_string_inheritance_for_mcp_compatibility(self):
        """Test that ToolState inherits from str for MCP server compatibility."""
        assert isinstance(ToolState.ENABLED, str)
        assert str(ToolState.ENABLED) == "ToolState.ENABLED"

    def test_tool_state_for_airs_tool_management(self):
        """Test ToolState usage in AIRS tool lifecycle management."""
        # Test state transitions that might occur in AIRS tool management
        security_states = [
            ToolState.ENABLED,  # Normal AIRS scanning tool operation
            ToolState.DISABLED_SECURITY_RISK,  # Tool flagged as security risk
            ToolState.DISABLED_ERROR,  # Tool experiencing errors during scanning
            ToolState.DISABLED_DUPLICATE,  # Duplicate AIRS tool detected
            ToolState.DISABLED_HIDDEN_MODE  # Tool hidden for maintenance
        ]

        for state in security_states:
            assert isinstance(state, str)
            assert "disabled" in state or state == "enabled"


class TestBaseTool:
    """Test suite for BaseTool class used in AIRS MCP server operations."""

    @pytest.fixture
    def pan_inline_scan_schema(self):
        """Create input schema for pan_inline_scan tool from AIRS server."""
        return {
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "User prompt to be scanned for security threats"
                },
                "response": {
                    "type": "string",
                    "description": "AI model response to be scanned for security threats"
                }
            },
            "anyOf": [
                {"required": ["prompt"]},
                {"required": ["response"]},
                {"required": ["prompt", "response"]}
            ]
        }

    @pytest.fixture
    def pan_batch_scan_schema(self):
        """Create input schema for pan_batch_scan tool from AIRS server."""
        return {
            "type": "object",
            "properties": {
                "scan_contents": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "prompt": {"type": "string"},
                            "response": {"type": "string"}
                        }
                    },
                    "description": "Array of scan content objects for batch processing",
                    "maxItems": 5  # MAX_NUMBER_OF_BATCH_SCAN_OBJECTS
                }
            },
            "required": ["scan_contents"]
        }

    @pytest.fixture
    def airs_inline_scan_tool_data(self, pan_inline_scan_schema):
        """Create AIRS inline scan tool data matching pan_security_server.py."""
        return {
            "name": "pan_inline_scan",
            "description": "Submit a single Prompt and/or Model-Response to be scanned synchronously for security threats",
            "inputSchema": pan_inline_scan_schema,
            "server_name": "aisecurity-scan-server",
            "state": ToolState.ENABLED
        }

    def test_base_tool_creation_for_airs_inline_scan(self, airs_inline_scan_tool_data):
        """Test BaseTool creation for AIRS inline scanning tool."""
        inline_scan_tool = BaseTool(**airs_inline_scan_tool_data)

        assert inline_scan_tool.name == "pan_inline_scan"
        assert "synchronously for security threats" in inline_scan_tool.description
        assert inline_scan_tool.server_name == "aisecurity-scan-server"
        assert inline_scan_tool.state == ToolState.ENABLED
        assert "prompt" in inline_scan_tool.inputSchema["properties"]
        assert "response" in inline_scan_tool.inputSchema["properties"]

    def test_base_tool_creation_for_airs_batch_scan(self, pan_batch_scan_schema):
        """Test BaseTool creation for AIRS batch scanning tool."""
        batch_scan_tool = BaseTool(
            name="pan_batch_scan",
            description="Submit multiple Scan Contents for asynchronous batch scanning",
            inputSchema=pan_batch_scan_schema,
            server_name="aisecurity-scan-server"
        )

        assert batch_scan_tool.name == "pan_batch_scan"
        assert "asynchronous batch scanning" in batch_scan_tool.description
        assert batch_scan_tool.inputSchema["properties"]["scan_contents"]["maxItems"] == 5

    def test_base_tool_creation_for_airs_scan_results(self):
        """Test BaseTool creation for AIRS scan results retrieval tool."""
        scan_results_schema = {
            "type": "object",
            "properties": {
                "scan_ids": {
                    "type": "array",
                    "items": {"type": "string", "format": "uuid"},
                    "description": "List of Scan IDs (UUID strings) to retrieve results for"
                }
            },
            "required": ["scan_ids"]
        }

        scan_results_tool = BaseTool(
            name="pan_get_scan_results",
            description="Retrieve Scan Results with a list of Scan IDs",
            inputSchema=scan_results_schema,
            server_name="aisecurity-scan-server"
        )

        assert scan_results_tool.name == "pan_get_scan_results"
        assert "uuid" in scan_results_tool.inputSchema["properties"]["scan_ids"]["items"]["format"]

    def test_base_tool_creation_for_airs_scan_reports(self):
        """Test BaseTool creation for AIRS scan reports retrieval tool."""
        scan_reports_schema = {
            "type": "object",
            "properties": {
                "report_ids": {
                    "type": "array",
                    "items": {"type": "string", "pattern": "^R[0-9a-f-]{36}$"},
                    "description": "List of Scan Report IDs (UUID prefixed with 'R')"
                }
            },
            "required": ["report_ids"]
        }

        scan_reports_tool = BaseTool(
            name="pan_get_scan_reports",
            description="Retrieve Scan Reports with a list of Scan Report IDs",
            inputSchema=scan_reports_schema,
            server_name="aisecurity-scan-server"
        )

        assert scan_reports_tool.name == "pan_get_scan_reports"
        assert "R[0-9a-f-]{36}" in scan_reports_tool.inputSchema["properties"]["report_ids"]["items"]["pattern"]

    def test_get_argument_descriptions_for_airs_tools(self, airs_inline_scan_tool_data):
        """Test argument descriptions generation for AIRS scanning tools."""
        airs_tool = BaseTool(**airs_inline_scan_tool_data)
        descriptions = airs_tool.get_argument_descriptions()

        # Should handle anyOf requirements properly
        assert len(descriptions) == 2

        prompt_desc = next((desc for desc in descriptions if "prompt" in desc), None)
        response_desc = next((desc for desc in descriptions if "response" in desc), None)

        assert prompt_desc is not None
        assert response_desc is not None
        assert "security threats" in prompt_desc
        assert "security threats" in response_desc

    def test_to_mcp_tool_conversion_for_airs_relay(self, airs_inline_scan_tool_data):
        """Test conversion to MCP Tool for AIRS relay operations."""
        airs_annotations = {
            "ai_profile": "default",
            "scan_type": "inline",
            "api_endpoint": "https://ai-runtime-security.api.paloaltonetworks.com"
        }
        airs_inline_scan_tool_data["annotations"] = airs_annotations

        airs_tool = BaseTool(**airs_inline_scan_tool_data)
        mcp_tool = airs_tool.to_mcp_tool()

        assert isinstance(mcp_tool, types.Tool)
        assert mcp_tool.name == "pan_inline_scan"
        assert mcp_tool.annotations.ai_profile == "default"
        assert mcp_tool.annotations.scan_type == "inline"

        # Server-specific fields should be removed for MCP relay
        assert not hasattr(mcp_tool, "server_name")
        assert not hasattr(mcp_tool, "state")

    def test_base_tool_with_airs_security_states(self, airs_inline_scan_tool_data):
        """Test BaseTool with different AIRS security states."""
        # Test security states relevant to AIRS operations
        airs_states_to_test = [
            ToolState.ENABLED,  # Normal AIRS operation
            ToolState.DISABLED_ERROR,  # AIRS API errors
            ToolState.DISABLED_SECURITY_RISK  # Tool flagged by security policy
        ]

        for state in airs_states_to_test:
            airs_inline_scan_tool_data["state"] = state
            airs_tool = BaseTool(**airs_inline_scan_tool_data)
            assert airs_tool.state == state


class TestInternalTool:
    """Test suite for InternalTool class used in AIRS tool registry management."""

    @pytest.fixture
    def airs_batch_scan_tool_data(self):
        """Create AIRS batch scan tool data for testing."""
        return {
            "name": "pan_batch_scan",
            "description": "Submit multiple Scan Contents containing prompts/model-responses for asynchronous scanning",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "scan_contents": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "prompt": {"type": "string"},
                                "response": {"type": "string"}
                            }
                        },
                        "maxItems": 5  # MAX_NUMBER_OF_BATCH_SCAN_OBJECTS
                    }
                },
                "required": ["scan_contents"]
            },
            "server_name": "aisecurity-scan-server",
            "state": ToolState.ENABLED
        }

    def test_internal_tool_creation_with_airs_batch_scan(self, airs_batch_scan_tool_data):
        """Test InternalTool creation for AIRS batch scanning with hash generation."""
        batch_scan_tool = InternalTool(**airs_batch_scan_tool_data)

        assert batch_scan_tool.name == "pan_batch_scan"
        assert "asynchronous scanning" in batch_scan_tool.description
        assert batch_scan_tool.server_name == "aisecurity-scan-server"
        assert batch_scan_tool.state == ToolState.ENABLED
        assert batch_scan_tool.md5_hash != ""
        assert len(batch_scan_tool.md5_hash) == 32

    def test_internal_tool_hash_computation_for_airs_deduplication(self, airs_batch_scan_tool_data):
        """Test MD5 hash computation for AIRS tool deduplication."""
        batch_scan_tool = InternalTool(**airs_batch_scan_tool_data)

        # Manually compute expected hash for AIRS tool verification
        payload = {
            "server_name": "aisecurity-scan-server",
            "tool_name": "pan_batch_scan",
            "description": "Submit multiple Scan Contents containing prompts/model-responses for asynchronous scanning",
            "input_schema": airs_batch_scan_tool_data["inputSchema"],
        }
        json_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected_hash = hashlib.md5(json_str.encode("utf-8")).hexdigest()

        assert batch_scan_tool.md5_hash == expected_hash

    def test_internal_tool_hash_consistency_for_airs_caching(self, airs_batch_scan_tool_data):
        """Test that identical AIRS tools produce identical hashes for caching."""
        airs_tool_1 = InternalTool(**airs_batch_scan_tool_data)
        airs_tool_2 = InternalTool(**airs_batch_scan_tool_data)

        assert airs_tool_1.md5_hash == airs_tool_2.md5_hash

    def test_internal_tool_hash_uniqueness_for_different_airs_tools(self, airs_batch_scan_tool_data):
        """Test that different AIRS tools produce different hashes."""
        batch_scan_tool = InternalTool(**airs_batch_scan_tool_data)

        # Create scan results tool with different configuration
        scan_results_data = airs_batch_scan_tool_data.copy()
        scan_results_data["name"] = "pan_get_scan_results"
        scan_results_data["description"] = "Retrieve Scan Results with a list of Scan IDs"
        scan_results_data["inputSchema"] = {
            "type": "object",
            "properties": {
                "scan_ids": {
                    "type": "array",
                    "items": {"type": "string", "format": "uuid"}
                }
            },
            "required": ["scan_ids"]
        }
        scan_results_tool = InternalTool(**scan_results_data)

        assert batch_scan_tool.md5_hash != scan_results_tool.md5_hash

    def test_internal_tool_to_dict_for_airs_storage(self, airs_batch_scan_tool_data):
        """Test conversion to dictionary for AIRS tool storage."""
        airs_tool = InternalTool(**airs_batch_scan_tool_data)
        storage_dict = airs_tool.to_dict()

        expected_keys = ["name", "description", "input_schema", "server_name", "state", "md5_hash"]
        assert all(key in storage_dict for key in expected_keys)

        assert storage_dict["name"] == "pan_batch_scan"
        assert storage_dict["server_name"] == "aisecurity-scan-server"
        assert storage_dict["state"] == ToolState.ENABLED
        assert storage_dict["md5_hash"] == airs_tool.md5_hash
        assert storage_dict["input_schema"]["properties"]["scan_contents"]["maxItems"] == 5

    def test_internal_tool_with_airs_api_constraints(self):
        """Test InternalTool with AIRS API constraints and limits."""
        # Test tool with MAX_NUMBER_OF_SCAN_IDS constraint
        scan_ids_schema = {
            "type": "object",
            "properties": {
                "scan_ids": {
                    "type": "array",
                    "items": {"type": "string", "format": "uuid"},
                    "maxItems": 100,  # MAX_NUMBER_OF_SCAN_IDS
                    "description": "List of Scan IDs (UUID strings)"
                }
            },
            "required": ["scan_ids"]
        }

        airs_constraint_tool = InternalTool(
            name="pan_get_scan_results",
            description="Retrieve Scan Results with API batch size constraints",
            inputSchema=scan_ids_schema,
            server_name="aisecurity-scan-server"
        )

        assert airs_constraint_tool.md5_hash != ""
        storage_dict = airs_constraint_tool.to_dict()
        assert storage_dict["input_schema"]["properties"]["scan_ids"]["maxItems"] == 100


class TestRelayTool:
    """Test suite for RelayTool class used for AIRS LLM presentation."""

    @pytest.fixture
    def airs_inline_scan_relay_data(self):
        """Create AIRS inline scan relay tool data."""
        return {
            "name": "pan_inline_scan",
            "description": "Submit a single Prompt and/or Model-Response to be scanned synchronously for security threats",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "User prompt to be scanned for security threats"
                    },
                    "response": {
                        "type": "string",
                        "description": "AI model response to be scanned for security threats"
                    }
                },
                "anyOf": [
                    {"required": ["prompt"]},
                    {"required": ["response"]},
                    {"required": ["prompt", "response"]}
                ]
            },
            "server_name": "aisecurity-scan-server",
            "state": ToolState.ENABLED
        }

    def test_relay_tool_creation_for_airs_llm_presentation(self, airs_inline_scan_relay_data):
        """Test RelayTool creation for AIRS LLM presentation."""
        airs_relay_tool = RelayTool(**airs_inline_scan_relay_data)

        assert airs_relay_tool.name == "pan_inline_scan"
        assert "synchronously for security threats" in airs_relay_tool.description
        assert airs_relay_tool.server_name == "aisecurity-scan-server"
        assert airs_relay_tool.state == ToolState.ENABLED

    def test_relay_tool_format_for_llm_airs_inline_scan(self, airs_inline_scan_relay_data):
        """Test format_for_llm method with AIRS inline scan tool."""
        airs_relay_tool = RelayTool(**airs_inline_scan_relay_data)
        llm_formatted_output = airs_relay_tool.format_for_llm()

        # Check AIRS-specific formatting for LLM consumption
        assert "Tool: pan_inline_scan" in llm_formatted_output
        assert "Server: aisecurity-scan-server" in llm_formatted_output
        assert "synchronously for security threats" in llm_formatted_output
        assert "Arguments:" in llm_formatted_output
        assert "prompt:" in llm_formatted_output
        assert "response:" in llm_formatted_output
        assert "security threats" in llm_formatted_output

    def test_relay_tool_format_for_llm_airs_batch_scan(self):
        """Test format_for_llm with AIRS batch scan tool."""
        airs_batch_relay_tool = RelayTool(
            name="pan_batch_scan",
            description="Submit multiple Scan Contents for asynchronous batch scanning",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_contents": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "prompt": {"type": "string"},
                                "response": {"type": "string"}
                            }
                        },
                        "description": "Array of scan content objects for batch processing"
                    }
                },
                "required": ["scan_contents"]
            },
            server_name="aisecurity-scan-server"
        )

        llm_formatted_output = airs_batch_relay_tool.format_for_llm()

        assert "Tool: pan_batch_scan" in llm_formatted_output
        assert "asynchronous batch scanning" in llm_formatted_output
        assert "scan_contents:" in llm_formatted_output
        assert "(required)" in llm_formatted_output
        assert "batch processing" in llm_formatted_output

    def test_relay_tool_format_for_llm_airs_scan_results(self):
        """Test format_for_llm with AIRS scan results retrieval tool."""
        airs_results_relay_tool = RelayTool(
            name="pan_get_scan_results",
            description="Retrieve Scan Results with a list of Scan IDs",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_ids": {
                        "type": "array",
                        "items": {"type": "string", "format": "uuid"},
                        "description": "List of Scan IDs (UUID strings) to retrieve results for"
                    }
                },
                "required": ["scan_ids"]
            },
            server_name="aisecurity-scan-server"
        )

        llm_formatted_output = airs_results_relay_tool.format_for_llm()

        assert "Tool: pan_get_scan_results" in llm_formatted_output
        assert "Retrieve Scan Results" in llm_formatted_output
        assert "scan_ids:" in llm_formatted_output
        assert "UUID strings" in llm_formatted_output
        assert "(required)" in llm_formatted_output

    def test_relay_tool_with_airs_error_states(self, airs_inline_scan_relay_data):
        """Test RelayTool with AIRS error states for monitoring."""
        airs_error_states = [
            ToolState.ENABLED,
            ToolState.DISABLED_ERROR,  # AIRS API errors
            ToolState.DISABLED_SECURITY_RISK  # Security policy violations
        ]

        for state in airs_error_states:
            airs_inline_scan_relay_data["state"] = state
            airs_relay_tool = RelayTool(**airs_inline_scan_relay_data)

            assert airs_relay_tool.state == state

            # format_for_llm should work regardless of AIRS tool state
            llm_formatted_output = airs_relay_tool.format_for_llm()
            assert "Tool: pan_inline_scan" in llm_formatted_output


class TestAIRSToolIntegration:
    """Integration tests for AIRS tool classes working together."""

    def test_all_airs_tool_types_with_same_data(self):
        """Test that all tool types can be created with compatible AIRS data."""
        common_airs_data = {
            "name": "pan_integrated_airs_scanner",
            "description": "Integrated AIRS scanning and analysis platform",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Content to scan for security threats via AIRS API"
                    }
                }
            },
            "server_name": "aisecurity-scan-server",
            "state": ToolState.ENABLED
        }

        # Create all AIRS tool types
        base_airs_tool = BaseTool(**common_airs_data)
        internal_airs_tool = InternalTool(**common_airs_data)
        relay_airs_tool = RelayTool(**common_airs_data)

        # All should have same basic AIRS properties
        airs_tools = [base_airs_tool, internal_airs_tool, relay_airs_tool]
        for tool in airs_tools:
            assert tool.name == "pan_integrated_airs_scanner"
            assert "AIRS" in tool.description
            assert tool.server_name == "aisecurity-scan-server"
            assert tool.state == ToolState.ENABLED

    def test_airs_tool_conversion_compatibility_for_mcp_relay(self):
        """Test compatibility between AIRS tool types for MCP relay."""
        # Create an InternalTool for AIRS scanning
        internal_airs_tool = InternalTool(
            name="pan_airs_converter",
            description="AIRS threat analysis tool for MCP relay testing",
            inputSchema={"type": "string"},
            server_name="aisecurity-scan-server"
        )

        # Convert to MCP tool for relay
        mcp_airs_tool = internal_airs_tool.to_mcp_tool()

        # Create RelayTool from same AIRS data
        relay_airs_tool = RelayTool(
            name=internal_airs_tool.name,
            description=internal_airs_tool.description,
            inputSchema=internal_airs_tool.inputSchema,
            server_name=internal_airs_tool.server_name,
            state=internal_airs_tool.state
        )

        # Both should produce same MCP tool for relay
        relay_mcp_airs_tool = relay_airs_tool.to_mcp_tool()

        assert mcp_airs_tool.name == relay_mcp_airs_tool.name
        assert mcp_airs_tool.description == relay_mcp_airs_tool.description
        assert mcp_airs_tool.inputSchema == relay_mcp_airs_tool.inputSchema

    def test_airs_tool_serialization_for_persistent_storage(self):
        """Test AIRS tool serialization for persistent storage."""
        original_airs_tool = InternalTool(
            name="pan_airs_serialization_scanner",
            description="AIRS scanner for serialization and storage testing",
            inputSchema={
                "type": "object",
                "properties": {
                    "ai_profile": {
                        "type": "string",
                        "description": "AI Profile for AIRS scanning configuration"
                    },
                    "scan_content": {
                        "type": "object",
                        "description": "Content object for AIRS threat analysis"
                    }
                }
            },
            server_name="aisecurity-scan-server",
            state=ToolState.ENABLED
        )

        # Serialize to dict for storage
        airs_tool_dict = original_airs_tool.to_dict()

        # Create new AIRS tool from dict (simulating database retrieval)
        recreated_airs_tool = InternalTool(
            name=airs_tool_dict["name"],
            description=airs_tool_dict["description"],
            inputSchema=airs_tool_dict["input_schema"],
            server_name=airs_tool_dict["server_name"],
            state=airs_tool_dict["state"]
        )

        # Should have same hash (same AIRS content)
        assert original_airs_tool.md5_hash == recreated_airs_tool.md5_hash
        assert original_airs_tool.name == recreated_airs_tool.name
        assert original_airs_tool.state == recreated_airs_tool.state

    def test_airs_tool_inheritance_chain_for_mcp_server(self):
        """Test the inheritance chain of AIRS tool classes for MCP server operations."""
        airs_mcp_tool = InternalTool(
            name="pan_airs_mcp_scanner",
            description="AIRS MCP server scanning tool",
            inputSchema={},
            server_name="aisecurity-scan-server"
        )

        # Should be instance of all parent classes for MCP integration
        assert isinstance(airs_mcp_tool, InternalTool)
        assert isinstance(airs_mcp_tool, BaseTool)
        assert isinstance(airs_mcp_tool, types.Tool)

        # Should have methods from all levels for AIRS functionality
        assert hasattr(airs_mcp_tool, "compute_hash")  # InternalTool for registry
        assert hasattr(airs_mcp_tool, "get_argument_descriptions")  # BaseTool for docs
        assert hasattr(airs_mcp_tool, "to_mcp_tool")  # BaseTool for MCP relay

        # Should have all required attributes for AIRS operations
        assert hasattr(airs_mcp_tool, "md5_hash")  # InternalTool for deduplication
        assert hasattr(airs_mcp_tool, "server_name")  # BaseTool for server tracking
        assert hasattr(airs_mcp_tool, "state")  # BaseTool for AIRS state management
        assert hasattr(airs_mcp_tool, "name")  # types.Tool for identification
        assert hasattr(airs_mcp_tool, "description")  # types.Tool for documentation
        assert hasattr(airs_mcp_tool, "inputSchema")  # types.Tool for MCP understanding

    def test_airs_tool_with_simple_scan_content_type(self):
        """Test AIRS tools with SimpleScanContent TypedDict structure."""
        # Test tool that matches SimpleScanContent from pan_security_server.py
        simple_scan_content_schema = {
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "User prompt for AIRS scanning"
                },
                "response": {
                    "type": "string",
                    "description": "AI model response for AIRS scanning"
                }
            }
        }

        airs_simple_tool = RelayTool(
            name="pan_simple_content_scanner",
            description="AIRS tool using SimpleScanContent structure",
            inputSchema=simple_scan_content_schema,
            server_name="aisecurity-scan-server"
        )

        llm_output = airs_simple_tool.format_for_llm()

        assert "pan_simple_content_scanner" in llm_output
        assert "SimpleScanContent" in airs_simple_tool.description
        assert "prompt:" in llm_output
        assert "response:" in llm_output
        assert "AIRS scanning" in llm_output
