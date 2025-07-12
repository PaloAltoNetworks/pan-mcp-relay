"""
Unit tests for the tool module.

This module contains comprehensive tests for the tool classes including
ToolState enum, BaseTool, InternalTool, and RelayTool classes used in
AI security MCP relay operations.
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
    """Test suite for ToolState enum used in AI security scanning."""

    def test_tool_state_values(self):
        """Test that ToolState enum has correct security-related values."""
        assert ToolState.ENABLED == "enabled"
        assert ToolState.DISABLED_HIDDEN_MODE == "disabled - hidden_mode"
        assert ToolState.DISABLED_DUPLICATE == "disabled - duplicate"
        assert ToolState.DISABLED_SECURITY_RISK == "disabled - security risk"
        assert ToolState.DISABLED_ERROR == "disabled - error"

    def test_tool_state_string_inheritance(self):
        """Test that ToolState inherits from str for security filtering operations."""
        assert isinstance(ToolState.ENABLED, str)
        assert str(ToolState.ENABLED) == "ToolState.ENABLED"

    def test_tool_state_equality_for_security_filtering(self):
        """Test ToolState equality comparisons for security policy enforcement."""
        assert ToolState.ENABLED == "enabled"
        assert ToolState.DISABLED_DUPLICATE == "disabled - duplicate"
        assert ToolState.ENABLED != ToolState.DISABLED_SECURITY_RISK

    def test_tool_state_membership_for_compliance(self):
        """Test ToolState membership operations for compliance checking."""
        all_states = [state for state in ToolState]
        assert len(all_states) == 5
        assert ToolState.ENABLED in all_states
        assert ToolState.DISABLED_HIDDEN_MODE in all_states


class TestBaseTool:
    """Test suite for BaseTool class used in distributed AI security systems."""

    @pytest.fixture
    def ai_text_analysis_schema(self):
        """Create sample input schema for AI text analysis tool."""
        return {
            "type": "object",
            "properties": {
                "text_content": {
                    "type": "string",
                    "description": "Text content to analyze for security threats"
                },
                "analysis_depth": {
                    "type": "integer",
                    "description": "Depth of security analysis (1-5 scale)"
                },
                "scan_options": {
                    "type": "object",
                    "description": "Advanced scanning configuration",
                    "properties": {
                        "check_malware": {"type": "boolean"},
                        "check_phishing": {"type": "boolean"}
                    }
                }
            },
            "required": ["text_content"]
        }

    @pytest.fixture
    def security_scan_tool_data(self, ai_text_analysis_schema):
        """Create security scanning tool data for testing."""
        return {
            "name": "pan_security_text_scanner",
            "description": "AI-powered text security scanner for threat detection",
            "inputSchema": ai_text_analysis_schema,
            "server_name": "pan_aisecurity_server",
            "state": ToolState.ENABLED
        }

    def test_base_tool_creation_minimal_scanner(self):
        """Test BaseTool creation with minimal required fields for basic scanner."""
        basic_scanner = BaseTool(
            name="basic_malware_detector",
            description="Minimal malware detection tool",
            inputSchema={},
            server_name="security_server"
        )

        assert basic_scanner.name == "basic_malware_detector"
        assert basic_scanner.description == "Minimal malware detection tool"
        assert basic_scanner.inputSchema == {}
        assert basic_scanner.server_name == "security_server"
        assert basic_scanner.state == ToolState.ENABLED  # Default value

    def test_base_tool_creation_full_security_scanner(self, security_scan_tool_data):
        """Test BaseTool creation with all fields for comprehensive security scanner."""
        security_tool = BaseTool(**security_scan_tool_data)

        assert security_tool.name == "pan_security_text_scanner"
        assert security_tool.description == "AI-powered text security scanner for threat detection"
        assert security_tool.server_name == "pan_aisecurity_server"
        assert security_tool.state == ToolState.ENABLED
        assert "text_content" in security_tool.inputSchema["properties"]

    def test_base_tool_with_different_security_states(self, security_scan_tool_data):
        """Test BaseTool creation with different security states for compliance."""
        security_states_to_test = [
            ToolState.ENABLED,
            ToolState.DISABLED_HIDDEN_MODE,
            ToolState.DISABLED_DUPLICATE,
            ToolState.DISABLED_SECURITY_RISK,
            ToolState.DISABLED_ERROR
        ]

        for state in security_states_to_test:
            security_scan_tool_data["state"] = state
            security_tool = BaseTool(**security_scan_tool_data)
            assert security_tool.state == state

    def test_base_tool_with_security_annotations(self, security_scan_tool_data):
        """Test BaseTool with security-related annotations."""
        security_annotations = {
            "category": "ai_security",
            "version": "2.1.0",
            "author": "palo_alto_networks",
            "compliance_level": "enterprise",
            "threat_detection": "advanced"
        }
        security_scan_tool_data["annotations"] = security_annotations

        security_tool = BaseTool(**security_scan_tool_data)
        assert security_tool.annotations.category == security_annotations["category"]
        assert security_tool.annotations.version == security_annotations["version"]
        assert security_tool.annotations.author == security_annotations["author"]

    def test_get_argument_descriptions_with_security_params(self, security_scan_tool_data):
        """Test argument descriptions generation with security parameters."""
        security_tool = BaseTool(**security_scan_tool_data)
        descriptions = security_tool.get_argument_descriptions()

        assert len(descriptions) == 3

        # Check required security parameter
        text_param = next((desc for desc in descriptions if "text_content" in desc), None)
        assert text_param is not None
        assert "(required)" in text_param
        assert "Text content to analyze for security threats" in text_param

        # Check optional analysis parameter
        depth_param = next((desc for desc in descriptions if "analysis_depth" in desc), None)
        assert depth_param is not None
        assert "(required)" not in depth_param
        assert "Depth of security analysis" in depth_param

    def test_get_argument_descriptions_no_security_properties(self):
        """Test argument descriptions with schema without security properties."""
        simple_scanner = BaseTool(
            name="simple_hash_checker",
            description="Simple file hash security checker",
            inputSchema={"type": "string"},
            server_name="hash_server"
        )

        descriptions = simple_scanner.get_argument_descriptions()
        assert descriptions == []

    def test_get_argument_descriptions_missing_security_description(self, security_scan_tool_data):
        """Test argument descriptions when security parameter has no description."""
        # Remove description from security parameter
        del security_scan_tool_data["inputSchema"]["properties"]["text_content"]["description"]

        security_tool = BaseTool(**security_scan_tool_data)
        descriptions = security_tool.get_argument_descriptions()

        # Should still generate description with default text
        text_param = next((desc for desc in descriptions if "text_content" in desc), None)
        assert text_param is not None
        assert "No description" in text_param

    def test_get_argument_descriptions_empty_security_schema(self):
        """Test argument descriptions with empty security input schema."""
        empty_scanner = BaseTool(
            name="placeholder_security_tool",
            description="Security tool with no parameters",
            inputSchema={},
            server_name="security_server"
        )

        descriptions = empty_scanner.get_argument_descriptions()
        assert descriptions == []

    def test_to_mcp_tool_conversion_for_ai_relay(self, security_scan_tool_data):
        """Test conversion to standard MCP Tool for AI relay operations."""
        security_annotations = {"threat_level": "advanced", "scan_type": "comprehensive"}
        security_scan_tool_data["annotations"] = security_annotations

        security_base_tool = BaseTool(**security_scan_tool_data)
        mcp_security_tool = security_base_tool.to_mcp_tool()

        # Verify it's a standard MCP Tool for AI consumption
        assert isinstance(mcp_security_tool, types.Tool)
        assert mcp_security_tool.name == "pan_security_text_scanner"
        assert mcp_security_tool.description == "AI-powered text security scanner for threat detection"
        assert mcp_security_tool.inputSchema == security_scan_tool_data["inputSchema"]
        assert mcp_security_tool.annotations.threat_level == security_annotations["threat_level"]

        # Verify it doesn't have BaseTool specific fields (server info removed for AI)
        assert not hasattr(mcp_security_tool, "server_name")
        assert not hasattr(mcp_security_tool, "state")

    def test_base_tool_validation_missing_server_info(self):
        """Test BaseTool validation with missing required server information."""
        # Missing server_name for distributed security system
        with pytest.raises(ValidationError) as exc_info:
            BaseTool(
                name="orphaned_security_tool",
                description="Security tool without server info",
                inputSchema={}
            )

        error_details = str(exc_info.value)
        assert "server_name" in error_details

    def test_base_tool_extra_security_fields_allowed(self, security_scan_tool_data):
        """Test that BaseTool allows extra security fields for extensibility."""
        security_scan_tool_data["threat_database_version"] = "v2024.01"
        security_scan_tool_data["compliance_metadata"] = {"sox": True, "gdpr": True}

        security_tool = BaseTool(**security_scan_tool_data)

        # Should not raise validation error for security extensions
        assert security_tool.name == "pan_security_text_scanner"
        # Extra security fields should be accessible
        assert hasattr(security_tool, "threat_database_version")
        assert security_tool.threat_database_version == "v2024.01"

    def test_base_tool_field_validation_for_security_state(self):
        """Test field type validation for security state."""
        # Invalid security state type
        with pytest.raises(ValidationError):
            BaseTool(
                name="invalid_state_tool",
                description="Tool with invalid security state",
                inputSchema={},
                server_name="security_server",
                state="invalid_security_state"  # Should be ToolState enum
            )

    def test_base_tool_inheritance_from_mcp_tool_for_ai(self, security_scan_tool_data):
        """Test that BaseTool properly inherits from types.Tool for AI integration."""
        ai_security_tool = BaseTool(**security_scan_tool_data)

        # Should have all MCP Tool attributes for AI consumption
        assert hasattr(ai_security_tool, "name")
        assert hasattr(ai_security_tool, "description")
        assert hasattr(ai_security_tool, "inputSchema")

        # Should be instance of MCP Tool for AI relay compatibility
        assert isinstance(ai_security_tool, types.Tool)


class TestInternalTool:
    """Test suite for InternalTool class used in security tool registry management."""

    @pytest.fixture
    def malware_detection_tool_data(self):
        """Create malware detection tool data for testing."""
        return {
            "name": "pan_malware_detector",
            "description": "Advanced AI malware detection and analysis tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_content": {
                        "type": "string",
                        "description": "Base64 encoded file content for malware scanning"
                    },
                    "scan_timeout": {
                        "type": "integer",
                        "description": "Maximum scan time in seconds"
                    }
                }
            },
            "server_name": "pan_security_cluster",
            "state": ToolState.ENABLED
        }

    def test_internal_tool_creation_with_hash_generation(self, malware_detection_tool_data):
        """Test InternalTool creation and MD5 hash generation for registry management."""
        malware_tool = InternalTool(**malware_detection_tool_data)

        assert malware_tool.name == "pan_malware_detector"
        assert malware_tool.description == "Advanced AI malware detection and analysis tool"
        assert malware_tool.server_name == "pan_security_cluster"
        assert malware_tool.state == ToolState.ENABLED
        assert malware_tool.md5_hash != ""
        assert len(malware_tool.md5_hash) == 32  # MD5 hash length for registry key

    def test_internal_tool_hash_computation_for_deduplication(self, malware_detection_tool_data):
        """Test MD5 hash computation for tool deduplication across servers."""
        malware_tool = InternalTool(**malware_detection_tool_data)

        # Manually compute expected hash for verification
        payload = {
            "server_name": "pan_security_cluster",
            "tool_name": "pan_malware_detector",
            "description": "Advanced AI malware detection and analysis tool",
            "input_schema": malware_detection_tool_data["inputSchema"],
        }
        json_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected_hash = hashlib.md5(json_str.encode("utf-8")).hexdigest()

        assert malware_tool.md5_hash == expected_hash

    def test_internal_tool_hash_consistency_across_instances(self, malware_detection_tool_data):
        """Test that identical security tools produce identical hashes for caching."""
        malware_tool_1 = InternalTool(**malware_detection_tool_data)
        malware_tool_2 = InternalTool(**malware_detection_tool_data)

        assert malware_tool_1.md5_hash == malware_tool_2.md5_hash

    def test_internal_tool_hash_uniqueness_for_different_tools(self, malware_detection_tool_data):
        """Test that different security tools produce different hashes for proper separation."""
        malware_tool = InternalTool(**malware_detection_tool_data)

        # Create phishing detection tool with different configuration
        phishing_data = malware_detection_tool_data.copy()
        phishing_data["description"] = "AI-powered phishing URL detection and blocking tool"
        phishing_tool = InternalTool(**phishing_data)

        assert malware_tool.md5_hash != phishing_tool.md5_hash

    def test_internal_tool_compute_hash_method_for_registry(self, malware_detection_tool_data):
        """Test compute_hash method directly for tool registry operations."""
        security_tool = InternalTool(**malware_detection_tool_data)
        computed_registry_hash = security_tool.compute_hash()

        assert computed_registry_hash == security_tool.md5_hash
        assert len(computed_registry_hash) == 32

    def test_internal_tool_hash_with_complex_security_schema(self):
        """Test hash computation with complex security scanning schema."""
        complex_security_schema = {
            "type": "object",
            "properties": {
                "threat_analysis": {
                    "type": "object",
                    "properties": {
                        "behavioral_analysis": {"type": "boolean"},
                        "signature_matching": {"type": "boolean"},
                        "ml_classification": {
                            "type": "array",
                            "items": {"type": "string"},
                            "enum": ["deep_learning", "random_forest", "svm"]
                        }
                    }
                },
                "scan_priority": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"]
                },
                "compliance_checks": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            }
        }

        advanced_security_tool = InternalTool(
            name="pan_advanced_threat_detector",
            description="Multi-vector AI threat detection system",
            inputSchema=complex_security_schema,
            server_name="pan_advanced_security_cluster"
        )

        assert advanced_security_tool.md5_hash != ""
        assert len(advanced_security_tool.md5_hash) == 32

    def test_internal_tool_to_dict_for_storage(self, malware_detection_tool_data):
        """Test conversion to dictionary for database storage."""
        security_tool = InternalTool(**malware_detection_tool_data)
        storage_dict = security_tool.to_dict()

        expected_storage_keys = ["name", "description", "input_schema", "server_name", "state", "md5_hash"]
        assert all(key in storage_dict for key in expected_storage_keys)

        assert storage_dict["name"] == "pan_malware_detector"
        assert storage_dict["description"] == "Advanced AI malware detection and analysis tool"
        assert storage_dict["server_name"] == "pan_security_cluster"
        assert storage_dict["state"] == ToolState.ENABLED
        assert storage_dict["md5_hash"] == security_tool.md5_hash
        assert storage_dict["input_schema"] == malware_detection_tool_data["inputSchema"]

    def test_internal_tool_to_dict_with_different_security_states(self, malware_detection_tool_data):
        """Test to_dict with different security tool states for compliance tracking."""
        security_states_to_test = [
            ToolState.ENABLED,
            ToolState.DISABLED_HIDDEN_MODE,
            ToolState.DISABLED_SECURITY_RISK
        ]

        for state in security_states_to_test:
            malware_detection_tool_data["state"] = state
            security_tool = InternalTool(**malware_detection_tool_data)
            storage_dict = security_tool.to_dict()

            assert storage_dict["state"] == state

    def test_internal_tool_model_post_init_hash_generation(self, malware_detection_tool_data):
        """Test that model_post_init is called during initialization for hash generation."""
        with patch.object(InternalTool, 'compute_hash', return_value="security_tool_hash_abc123") as mock_compute:
            security_tool = InternalTool(**malware_detection_tool_data)

            mock_compute.assert_called_once()
            assert security_tool.md5_hash == "security_tool_hash_abc123"

    def test_internal_tool_inherits_base_tool_security_functionality(self, malware_detection_tool_data):
        """Test that InternalTool inherits BaseTool security functionality."""
        security_tool = InternalTool(**malware_detection_tool_data)

        # Should have BaseTool security methods
        security_descriptions = security_tool.get_argument_descriptions()
        assert len(security_descriptions) == 2
        assert "file_content" in security_descriptions[0]

        # Should convert to MCP tool for AI relay
        mcp_security_tool = security_tool.to_mcp_tool()
        assert isinstance(mcp_security_tool, types.Tool)
        assert mcp_security_tool.name == "pan_malware_detector"

    def test_internal_tool_with_empty_input_schema_for_simple_scanner(self):
        """Test InternalTool with empty input schema for simple security scanner."""
        simple_security_tool = InternalTool(
            name="pan_simple_hash_checker",
            description="Simple file hash verification tool",
            inputSchema={},
            server_name="pan_basic_security_server"
        )

        assert simple_security_tool.md5_hash != ""
        storage_dict = simple_security_tool.to_dict()
        assert storage_dict["input_schema"] == {}

    def test_internal_tool_hash_with_unicode_security_content(self):
        """Test hash computation with unicode characters in security tool fields."""
        unicode_security_tool = InternalTool(
            name="pan_international_scanner_测试",
            description="International threat scanner with unicode support: 🛡️ 🔒",
            inputSchema={"type": "string"},
            server_name="pan_global_security_服务器"
        )

        assert unicode_security_tool.md5_hash != ""
        assert len(unicode_security_tool.md5_hash) == 32

        # Hash should be reproducible for unicode content
        unicode_security_tool_2 = InternalTool(
            name="pan_international_scanner_测试",
            description="International threat scanner with unicode support: 🛡️ 🔒",
            inputSchema={"type": "string"},
            server_name="pan_global_security_服务器"
        )

        assert unicode_security_tool.md5_hash == unicode_security_tool_2.md5_hash


class TestRelayTool:
    """Test suite for RelayTool class used for AI-LLM security tool presentation."""

    @pytest.fixture
    def url_security_scanner_data(self):
        """Create URL security scanner data for AI relay testing."""
        return {
            "name": "pan_url_threat_analyzer",
            "description": "AI-powered URL security scanner for phishing and malware detection",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to analyze for security threats and malicious content"
                    },
                    "scan_options": {
                        "type": "object",
                        "description": "Advanced scanning configuration for threat detection",
                        "properties": {
                            "check_reputation": {"type": "boolean", "description": "Enable reputation-based scanning"},
                            "deep_analysis": {"type": "boolean", "description": "Perform deep content analysis"}
                        }
                    }
                },
                "required": ["url"]
            },
            "server_name": "pan_url_security_cluster",
            "state": ToolState.ENABLED
        }

    def test_relay_tool_creation_for_ai_presentation(self, url_security_scanner_data):
        """Test RelayTool creation for AI-LLM presentation."""
        url_scanner_tool = RelayTool(**url_security_scanner_data)

        assert url_scanner_tool.name == "pan_url_threat_analyzer"
        assert url_scanner_tool.description == "AI-powered URL security scanner for phishing and malware detection"
        assert url_scanner_tool.server_name == "pan_url_security_cluster"
        assert url_scanner_tool.state == ToolState.ENABLED

    def test_relay_tool_format_for_llm_basic_security_scanner(self, url_security_scanner_data):
        """Test format_for_llm method with basic security scanner for AI consumption."""
        url_scanner_tool = RelayTool(**url_security_scanner_data)
        llm_formatted_output = url_scanner_tool.format_for_llm()

        # Check that all expected sections are present for AI understanding
        assert "Tool: pan_url_threat_analyzer" in llm_formatted_output
        assert "Server: pan_url_security_cluster" in llm_formatted_output
        assert "Description: AI-powered URL security scanner for phishing and malware detection" in llm_formatted_output
        assert "Arguments:" in llm_formatted_output
        assert "url:" in llm_formatted_output
        assert "URL to analyze for security threats" in llm_formatted_output
        assert "(required)" in llm_formatted_output

    def test_relay_tool_format_for_llm_with_security_parameters(self, url_security_scanner_data):
        """Test format_for_llm method showing required vs optional security parameters."""
        security_tool = RelayTool(**url_security_scanner_data)
        llm_formatted_output = security_tool.format_for_llm()

        # URL should be marked as required security parameter
        lines = llm_formatted_output.split('\n')
        url_line = next((line for line in lines if "url:" in line), "")
        assert "(required)" in url_line

        # Scan options should not be marked as required
        options_line = next((line for line in lines if "scan_options:" in line), "")
        assert "(required)" not in options_line

    def test_relay_tool_format_for_llm_no_arguments_simple_scanner(self):
        """Test format_for_llm with simple security tool that has no arguments."""
        simple_security_tool = RelayTool(
            name="pan_system_health_checker",
            description="Simple security system health monitoring tool",
            inputSchema={},
            server_name="pan_monitoring_server"
        )

        llm_formatted_output = simple_security_tool.format_for_llm()

        assert "Tool: pan_system_health_checker" in llm_formatted_output
        assert "Server: pan_monitoring_server" in llm_formatted_output
        assert "Description: Simple security system health monitoring tool" in llm_formatted_output
        assert "Arguments:" in llm_formatted_output

    def test_relay_tool_format_for_llm_string_schema_file_scanner(self):
        """Test format_for_llm with string-type schema for file scanning."""
        file_scanner_tool = RelayTool(
            name="pan_file_hash_verifier",
            description="File hash verification tool for integrity checking",
            inputSchema={"type": "string"},
            server_name="pan_file_security_server"
        )

        llm_formatted_output = file_scanner_tool.format_for_llm()

        # Should handle gracefully even without properties
        assert "Tool: pan_file_hash_verifier" in llm_formatted_output
        assert "Arguments:" in llm_formatted_output

    def test_relay_tool_format_for_llm_multiline_formatting_for_ai(self, url_security_scanner_data):
        """Test that format_for_llm produces properly formatted multiline output for AI consumption."""
        security_tool = RelayTool(**url_security_scanner_data)
        llm_formatted_output = security_tool.format_for_llm()

        lines = [line.strip() for line in llm_formatted_output.split('\n') if line.strip()]

        # Should have multiple non-empty lines for AI parsing
        assert len(lines) >= 4

        # Check line structure for AI understanding
        tool_line = next((line for line in lines if line.startswith("Tool:")), "")
        server_line = next((line for line in lines if line.startswith("Server:")), "")
        desc_line = next((line for line in lines if line.startswith("Description:")), "")
        args_line = next((line for line in lines if line.startswith("Arguments:")), "")

        assert tool_line != ""
        assert server_line != ""
        assert desc_line != ""
        assert args_line != ""

    def test_relay_tool_inherits_base_tool_security_functionality(self, url_security_scanner_data):
        """Test that RelayTool inherits BaseTool security functionality."""
        security_relay_tool = RelayTool(**url_security_scanner_data)

        # Should have BaseTool security methods
        security_descriptions = security_relay_tool.get_argument_descriptions()
        assert len(security_descriptions) == 2  # url and scan_options

        # Should convert to MCP tool for AI integration
        mcp_security_tool = security_relay_tool.to_mcp_tool()
        assert isinstance(mcp_security_tool, types.Tool)
        assert mcp_security_tool.name == "pan_url_threat_analyzer"

    def test_relay_tool_format_for_llm_with_complex_security_descriptions(self):
        """Test format_for_llm with complex security parameter descriptions."""
        complex_security_schema = {
            "type": "object",
            "properties": {
                "threat_intelligence_query": {
                    "type": "string",
                    "description": "Advanced threat intelligence query with multiple vectors including behavioral analysis, signature matching, and ML-based classification for comprehensive security assessment"
                },
                "compliance_parameters": {
                    "type": "string",
                    "description": "Compliance validation parameters with special characters: SOX§ GDPR® PCI-DSS™ HIPAA©"
                },
                "international_threat_data": {
                    "type": "string",
                    "description": "International threat intelligence: 威胁情报 🚨 الأمان السيبراني 🔒 Кибербезопасность"
                }
            },
            "required": ["threat_intelligence_query"]
        }

        complex_security_tool = RelayTool(
            name="pan_advanced_threat_intelligence",
            description="Advanced multi-vector threat intelligence and analysis platform",
            inputSchema=complex_security_schema,
            server_name="pan_advanced_security_cluster"
        )

        llm_formatted_output = complex_security_tool.format_for_llm()

        # Should handle all complex security cases for AI understanding
        assert "threat_intelligence_query:" in llm_formatted_output
        assert "compliance_parameters:" in llm_formatted_output
        assert "international_threat_data:" in llm_formatted_output
        assert "威胁情报 🚨" in llm_formatted_output
        assert "(required)" in llm_formatted_output

    def test_relay_tool_with_different_security_states(self, url_security_scanner_data):
        """Test RelayTool with different security states for compliance management."""
        security_states_to_test = [
            ToolState.ENABLED,
            ToolState.DISABLED_HIDDEN_MODE,
            ToolState.DISABLED_SECURITY_RISK
        ]

        for state in security_states_to_test:
            url_security_scanner_data["state"] = state
            security_tool = RelayTool(**url_security_scanner_data)

            assert security_tool.state == state

            # format_for_llm should work regardless of security state
            llm_formatted_output = security_tool.format_for_llm()
            assert "Tool: pan_url_threat_analyzer" in llm_formatted_output


class TestSecurityToolIntegration:
    """Integration tests for security tool classes working together in AI systems."""

    def test_all_security_tool_types_with_same_data(self):
        """Test that all security tool types can be created with compatible data."""
        common_security_data = {
            "name": "pan_integrated_threat_scanner",
            "description": "Integrated AI threat scanning and analysis platform",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "content": {"type": "string", "description": "Content to scan for security threats"}
                }
            },
            "server_name": "pan_integration_security_server",
            "state": ToolState.ENABLED
        }

        # Create all security tool types
        base_security_tool = BaseTool(**common_security_data)
        internal_security_tool = InternalTool(**common_security_data)
        relay_security_tool = RelayTool(**common_security_data)

        # All should have same basic security properties
        security_tools = [base_security_tool, internal_security_tool, relay_security_tool]
        for tool in security_tools:
            assert tool.name == "pan_integrated_threat_scanner"
            assert tool.description == "Integrated AI threat scanning and analysis platform"
            assert tool.server_name == "pan_integration_security_server"
            assert tool.state == ToolState.ENABLED

    def test_security_tool_conversion_compatibility_for_ai(self):
        """Test compatibility between different security tool types for AI integration."""
        # Create an InternalTool for security scanning
        internal_security_tool = InternalTool(
            name="pan_ai_threat_converter",
            description="AI threat analysis tool for conversion testing",
            inputSchema={"type": "string"},
            server_name="pan_conversion_security_server"
        )

        # Convert to MCP tool for AI consumption
        mcp_security_tool = internal_security_tool.to_mcp_tool()

        # Create RelayTool from same security data
        relay_security_tool = RelayTool(
            name=internal_security_tool.name,
            description=internal_security_tool.description,
            inputSchema=internal_security_tool.inputSchema,
            server_name=internal_security_tool.server_name,
            state=internal_security_tool.state
        )

        # Both should produce same MCP tool for AI relay
        relay_mcp_security_tool = relay_security_tool.to_mcp_tool()

        assert mcp_security_tool.name == relay_mcp_security_tool.name
        assert mcp_security_tool.description == relay_mcp_security_tool.description
        assert mcp_security_tool.inputSchema == relay_mcp_security_tool.inputSchema

    def test_security_tool_serialization_and_deserialization_for_storage(self):
        """Test security tool serialization and deserialization for database storage."""
        original_security_tool = InternalTool(
            name="pan_serialization_threat_scanner",
            description="Threat scanner for serialization and storage testing",
            inputSchema={
                "type": "object",
                "properties": {
                    "threat_data": {"type": "string", "description": "Threat intelligence data"}
                }
            },
            server_name="pan_serialization_security_server",
            state=ToolState.DISABLED_DUPLICATE
        )

        # Serialize to dict for database storage
        security_tool_dict = original_security_tool.to_dict()

        # Create new security tool from dict data (simulating database retrieval)
        recreated_security_tool = InternalTool(
            name=security_tool_dict["name"],
            description=security_tool_dict["description"],
            inputSchema=security_tool_dict["input_schema"],
            server_name=security_tool_dict["server_name"],
            state=security_tool_dict["state"]
        )

        # Should have same hash (same security content)
        assert original_security_tool.md5_hash == recreated_security_tool.md5_hash
        assert original_security_tool.name == recreated_security_tool.name
        assert original_security_tool.state == recreated_security_tool.state

    def test_security_tool_inheritance_chain_for_distributed_ai(self):
        """Test the inheritance chain of security tool classes for distributed AI systems."""
        distributed_security_tool = InternalTool(
            name="pan_distributed_ai_scanner",
            description="Distributed AI security scanning tool",
            inputSchema={},
            server_name="pan_distributed_security_cluster"
        )

        # Should be instance of all parent classes for proper AI integration
        assert isinstance(distributed_security_tool, InternalTool)
        assert isinstance(distributed_security_tool, BaseTool)
        assert isinstance(distributed_security_tool, types.Tool)

        # Should have methods from all levels for comprehensive functionality
        assert hasattr(distributed_security_tool, "compute_hash")  # InternalTool for registry
        assert hasattr(distributed_security_tool, "get_argument_descriptions")  # BaseTool for documentation
        assert hasattr(distributed_security_tool, "to_mcp_tool")  # BaseTool for AI relay

        # Should have all required attributes for distributed security operations
        assert hasattr(distributed_security_tool, "md5_hash")  # InternalTool for deduplication
        assert hasattr(distributed_security_tool, "server_name")  # BaseTool for server tracking
        assert hasattr(distributed_security_tool, "state")  # BaseTool for security state management
        assert hasattr(distributed_security_tool, "name")  # types.Tool for identification
        assert hasattr(distributed_security_tool, "description")  # types.Tool for documentation
        assert hasattr(distributed_security_tool, "inputSchema")  # types.Tool for AI understanding
