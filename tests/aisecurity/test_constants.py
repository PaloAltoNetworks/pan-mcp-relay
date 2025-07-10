"""Unit tests for MCP Relay application constants."""

import unittest
import pytest
from datetime import datetime
from pan_aisecurity_mcp.mcp_relay import constants


class TestServerNames(unittest.TestCase):
    """Test server name constants."""

    def test_security_server_name(self):
        assert constants.SECURITY_SERVER_NAME == "pan-aisecurity"
        assert isinstance(constants.SECURITY_SERVER_NAME, str)

    def test_mcp_relay_name(self):
        assert constants.MCP_RELAY_NAME == "pan-aisecurity-relay"
        assert isinstance(constants.MCP_RELAY_NAME, str)


class TestConfigurationLabels:
    """Test configuration label constants."""

    def test_environment_config_label(self):
        assert constants.ENVIRONMENT_CONFIG_LABEL == "env"
        assert isinstance(constants.ENVIRONMENT_CONFIG_LABEL, str)

    def test_mcp_server_config_label(self):
        assert constants.MCP_SERVER_CONFIG_LABEL == "mcpServers"
        assert isinstance(constants.MCP_SERVER_CONFIG_LABEL, str)

    def test_hidden_mode_label(self):
        assert constants.HIDDEN_MODE_LABEL == "hidden_mode"
        assert isinstance(constants.HIDDEN_MODE_LABEL, str)

    def test_hidden_mode_enabled(self):
        assert constants.HIDDEN_MODE_ENABLED == "enabled"
        assert isinstance(constants.HIDDEN_MODE_ENABLED, str)

    def test_mcp_relay_transport_sse(self):
        assert constants.MCP_RELAY_TRANSPORT_SSE == "sse"
        assert isinstance(constants.MCP_RELAY_TRANSPORT_SSE, str)

    def test_mcp_relay_transport_stdio(self):
        assert constants.MCP_RELAY_TRANSPORT_STDIO == "stdio"
        assert isinstance(constants.MCP_RELAY_TRANSPORT_STDIO, str)


class TestDefaultValues:
    """Test default value constants."""

    def test_tool_registry_cache_expiry_default(self):
        assert constants.TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT == 300
        assert isinstance(constants.TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT, int)
        assert constants.TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT > 0

    def test_max_downstream_servers_default(self):
        assert constants.MAX_DOWNSTREAM_SERVERS_DEFAULT == 32
        assert isinstance(constants.MAX_DOWNSTREAM_SERVERS_DEFAULT, int)
        assert constants.MAX_DOWNSTREAM_SERVERS_DEFAULT > 0

    def test_max_downstream_tools_default(self):
        assert constants.MAX_DOWNSTREAM_TOOLS_DEFAULT == 64
        assert isinstance(constants.MAX_DOWNSTREAM_TOOLS_DEFAULT, int)
        assert constants.MAX_DOWNSTREAM_TOOLS_DEFAULT > 0


class TestToolNames:
    """Test tool name constants."""

    def test_tool_name_list_downstream_servers_info(self):
        assert (
            constants.TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO
            == "list_downstream_servers_info"
        )
        assert isinstance(constants.TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO, str)
        assert len(constants.TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO) > 0

    def test_tool_name_pan_aisecurity_inline_scan(self):
        assert constants.TOOL_NAME_PAN_AISECURITY_INLINE_SCAN == "pan_inline_scan"
        assert isinstance(constants.TOOL_NAME_PAN_AISECURITY_INLINE_SCAN, str)
        assert len(constants.TOOL_NAME_PAN_AISECURITY_INLINE_SCAN) > 0


class TestSecurityScanToolConstants:
    """Test security scan tool constants."""

    def test_expected_security_scan_result_content_length(self):
        assert constants.EXPECTED_SECURITY_SCAN_RESULT_CONTENT_LENGTH == 1
        assert isinstance(constants.EXPECTED_SECURITY_SCAN_RESULT_CONTENT_LENGTH, int)
        assert constants.EXPECTED_SECURITY_SCAN_RESULT_CONTENT_LENGTH > 0

    def test_security_scan_response_action_block(self):
        assert constants.SECURITY_SCAN_RESPONSE_ACTION_BLOCK == "block"
        assert isinstance(constants.SECURITY_SCAN_RESPONSE_ACTION_BLOCK, str)
        assert len(constants.SECURITY_SCAN_RESPONSE_ACTION_BLOCK) > 0

    def test_security_scan_response_action_allow(self):
        assert constants.SECURITY_SCAN_RESPONSE_ACTION_ALLOW == "allow"
        assert isinstance(constants.SECURITY_SCAN_RESPONSE_ACTION_ALLOW, str)
        assert len(constants.SECURITY_SCAN_RESPONSE_ACTION_ALLOW) > 0


class TestConstantIntegrity:
    """Test constant integrity and relationships."""

    def test_transport_types_are_different(self):
        """Ensure transport types are distinct."""
        assert constants.MCP_RELAY_TRANSPORT_SSE != constants.MCP_RELAY_TRANSPORT_STDIO

    def test_scan_response_actions_are_different(self):
        """Ensure scan response actions are distinct."""
        assert (
            constants.SECURITY_SCAN_RESPONSE_ACTION_BLOCK
            != constants.SECURITY_SCAN_RESPONSE_ACTION_ALLOW
        )

    def test_server_names_are_different(self):
        """Ensure server names are distinct."""
        assert constants.SECURITY_SERVER_NAME != constants.MCP_RELAY_NAME

    def test_tool_names_are_different(self):
        """Ensure tool names are distinct."""
        assert (
            constants.TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO
            != constants.TOOL_NAME_PAN_AISECURITY_INLINE_SCAN
        )

    def test_default_values_are_reasonable(self):
        """Test that default values are within reasonable ranges."""
        assert (
            0 < constants.TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT <= 3600
        )  # Between 0 and 1 hour
        assert 0 < constants.MAX_DOWNSTREAM_SERVERS_DEFAULT <= 1000
        assert 0 < constants.MAX_DOWNSTREAM_TOOLS_DEFAULT <= 1000

    def test_max_tools_greater_than_max_servers(self):
        """Test logical relationship between max tools and servers."""
        assert (
            constants.MAX_DOWNSTREAM_TOOLS_DEFAULT
            >= constants.MAX_DOWNSTREAM_SERVERS_DEFAULT
        )


class TestConstantImmutability:
    """Test that constants maintain their expected values."""

    @pytest.mark.parametrize(
        "constant_name,expected_value",
        [
            ("SECURITY_SERVER_NAME", "pan-aisecurity"),
            ("MCP_RELAY_NAME", "pan-aisecurity-relay"),
            ("ENVIRONMENT_CONFIG_LABEL", "env"),
            ("MCP_SERVER_CONFIG_LABEL", "mcpServers"),
            ("HIDDEN_MODE_LABEL", "hidden_mode"),
            ("HIDDEN_MODE_ENABLED", "enabled"),
            ("MCP_RELAY_TRANSPORT_SSE", "sse"),
            ("MCP_RELAY_TRANSPORT_STDIO", "stdio"),
            ("TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT", 300),
            ("MAX_DOWNSTREAM_SERVERS_DEFAULT", 32),
            ("MAX_DOWNSTREAM_TOOLS_DEFAULT", 64),
            ("TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO", "list_downstream_servers_info"),
            ("TOOL_NAME_PAN_AISECURITY_INLINE_SCAN", "pan_inline_scan"),
            ("EXPECTED_SECURITY_SCAN_RESULT_CONTENT_LENGTH", 1),
            ("SECURITY_SCAN_RESPONSE_ACTION_BLOCK", "block"),
            ("SECURITY_SCAN_RESPONSE_ACTION_ALLOW", "allow"),
        ],
    )
    def test_constant_values(self, constant_name, expected_value):
        """Test that all constants have their expected values."""
        actual_value = getattr(constants, constant_name)
        assert actual_value == expected_value

    def test_all_string_constants_non_empty(self):
        """Test that all string constants are non-empty."""
        string_constants = [
            constants.SECURITY_SERVER_NAME,
            constants.MCP_RELAY_NAME,
            constants.ENVIRONMENT_CONFIG_LABEL,
            constants.MCP_SERVER_CONFIG_LABEL,
            constants.HIDDEN_MODE_LABEL,
            constants.HIDDEN_MODE_ENABLED,
            constants.MCP_RELAY_TRANSPORT_SSE,
            constants.MCP_RELAY_TRANSPORT_STDIO,
            constants.TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO,
            constants.TOOL_NAME_PAN_AISECURITY_INLINE_SCAN,
            constants.SECURITY_SCAN_RESPONSE_ACTION_BLOCK,
            constants.SECURITY_SCAN_RESPONSE_ACTION_ALLOW,
        ]

        for constant in string_constants:
            assert isinstance(constant, str)
            assert len(constant) > 0
            assert constant.strip() == constant  # No leading/trailing whitespace


class TestConstantTypes:
    """Test that constants have the correct types."""

    def test_string_constant_types(self):
        """Test string constants are strings."""
        string_constants = [
            "SECURITY_SERVER_NAME",
            "MCP_RELAY_NAME",
            "ENVIRONMENT_CONFIG_LABEL",
            "MCP_SERVER_CONFIG_LABEL",
            "HIDDEN_MODE_LABEL",
            "HIDDEN_MODE_ENABLED",
            "MCP_RELAY_TRANSPORT_SSE",
            "MCP_RELAY_TRANSPORT_STDIO",
            "TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO",
            "TOOL_NAME_PAN_AISECURITY_INLINE_SCAN",
            "SECURITY_SCAN_RESPONSE_ACTION_BLOCK",
            "SECURITY_SCAN_RESPONSE_ACTION_ALLOW",
        ]

        for constant_name in string_constants:
            constant_value = getattr(constants, constant_name)
            assert isinstance(constant_value, str)

    def test_integer_constant_types(self):
        """Test integer constants are integers."""
        integer_constants = [
            "TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT",
            "MAX_DOWNSTREAM_SERVERS_DEFAULT",
            "MAX_DOWNSTREAM_TOOLS_DEFAULT",
            "EXPECTED_SECURITY_SCAN_RESULT_CONTENT_LENGTH",
        ]

        for constant_name in integer_constants:
            constant_value = getattr(constants, constant_name)
            assert isinstance(constant_value, int)

    def test_datetime_constant_type(self):
        """Test datetime constant is datetime."""
        assert isinstance(constants.UNIX_EPOCH, datetime)
