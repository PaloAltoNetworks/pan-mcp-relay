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

"""Unit tests for Configuration classes."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError
from pydantic.types import SecretStr

from pan_mcp_relay.configuration import (
    Config,
    HttpMcpServer,
    McpRelayConfig,
    McpRelayConfigurationError,
    SseMcpServer,
    StdioMcpServer,
    make_validation_aliases,
)
from pan_mcp_relay.constants import (
    DEFAULT_API_ENDPOINT,
    MAX_MCP_SERVERS_DEFAULT,
    MAX_MCP_TOOLS_DEFAULT,
    TOOL_REGISTRY_CACHE_TTL_DEFAULT,
    TransportType,
)


def test_make_validation_aliases__when_called__generates_correct_aliases():
    """Tests that make_validation_aliases generates a correct set of aliases."""
    # Arrange
    field_name = "my_field_name"

    # Act
    aliases = make_validation_aliases(field_name)

    # Assert
    expected = [
        "my_field_name",
        "myFieldName",
        "MyFieldName",
        "my-field-name",
        "myfieldname",
    ]
    assert all(e in aliases.choices for e in expected)
    assert "my_field_name" in aliases.choices


class TestMcpRelayConfig:
    """Tests for the McpRelayConfig Pydantic model."""

    def test_mcp_relay_config__with_defaults__has_correct_values(self):
        """Tests that a default McpRelayConfig has the expected default values."""
        # Arrange & Act
        config = McpRelayConfig()

        # Assert
        assert config.api_key is None
        assert config.ai_profile is None
        assert config.api_endpoint == DEFAULT_API_ENDPOINT
        assert config.config_file is None
        assert config.transport == TransportType.stdio
        assert str(config.host) == "127.0.0.1"
        assert config.port == 8000
        assert config.tool_registry_cache_ttl == TOOL_REGISTRY_CACHE_TTL_DEFAULT
        assert config.max_mcp_servers == MAX_MCP_SERVERS_DEFAULT
        assert config.max_mcp_tools == MAX_MCP_TOOLS_DEFAULT
        assert config.dotenv == Path(".env")
        assert not config.show_config
        assert config.log_level is not None  # logging.DEBUG
        assert not config.use_system_ca
        assert config.custom_ca_file is None

    def test_mcp_relay_config__with_valid_data__parses_correctly(self):
        """Tests that McpRelayConfig parses a valid data dictionary."""
        # Arrange
        data = {
            "api_key": "test-key",
            "ai_profile": "test-profile",
            "api_endpoint": "https://service-us.api.aisecurity.paloaltonetworks.com",
            "transport": "sse",
            "host": "0.0.0.0",
            "port": 9000,
        }

        # Act
        config = McpRelayConfig(**data)

        # Assert
        assert isinstance(config.api_key, SecretStr)
        assert config.api_key.get_secret_value() == "test-key"
        assert config.ai_profile == "test-profile"
        assert config.api_endpoint == "https://service-us.api.aisecurity.paloaltonetworks.com"
        assert config.transport == TransportType.sse
        assert str(config.host) == "0.0.0.0"
        assert config.port == 9000

    @pytest.mark.parametrize(
        "field, value, error_message",
        [
            ("api_endpoint", "not-a-url", "String should match pattern"),
            ("port", 99999, "Input should be less than 65535"),
            ("port", 0, "Input should be greater than 0"),
            ("tool_registry_cache_ttl", 20, "Input should be greater than 30"),
            ("max_mcp_servers", 0, "Input should be greater than 0"),
            ("max_mcp_tools", -1, "Input should be greater than 0"),
        ],
    )
    def test_mcp_relay_config__with_invalid_data__raises_validation_error(self, field, value, error_message):
        """Tests that McpRelayConfig raises ValidationError for invalid field values."""
        # Arrange
        data = {field: value}

        # Act & Assert
        with pytest.raises(ValidationError, match=error_message):
            McpRelayConfig(**data)

    def test_mcp_relay_config__model_post_init__expands_env_vars(self):
        """Tests that model_post_init expands environment variables in string fields."""
        # Arrange
        with patch.dict(os.environ, {"TEST_PROFILE": "expanded-profile", "TEST_KEY": "expanded-key"}):
            data = {
                "ai_profile": "$TEST_PROFILE",
                "api_key": "${TEST_KEY}",
            }

            # Act
            config = McpRelayConfig(**data)

            # Assert
            assert config.ai_profile == "expanded-profile"
            assert config.api_key.get_secret_value() == "expanded-key"

    def test_mcp_relay_config__security_scanner_env__returns_correct_dict(self):
        """Tests that security_scanner_env returns the correct dictionary for the scanner."""
        # Arrange
        api_key = "my-secret-key"
        profile = "my-profile"
        endpoint = "https://service-us.api.aisecurity.paloaltonetworks.com"
        config = McpRelayConfig(
            api_key=api_key,
            ai_profile=profile,
            api_endpoint=endpoint,
        )

        # Act
        env_vars = config.security_scanner_env()

        # Assert
        from pan_mcp_relay.constants import ENV_AI_PROFILE, ENV_API_ENDPOINT, ENV_API_KEY

        assert env_vars[ENV_API_KEY] == api_key
        assert env_vars[ENV_AI_PROFILE] == profile
        assert env_vars[ENV_API_ENDPOINT] == endpoint

    @pytest.mark.parametrize("alias", ["api-key", "apiKey", "api_key", "ApiKey"])
    def test_mcp_relay_config__with_aliases__parses_correctly(self, alias):
        """Tests that field aliases are correctly handled during parsing."""
        # Arrange
        data = {alias: "some-key"}

        # Act
        config = McpRelayConfig(**data)

        # Assert
        assert config.api_key.get_secret_value() == "some-key"


class TestMcpServerTypes:
    """Tests for the various McpServer Pydantic models."""

    def test_stdio_mcp_server__with_valid_data__parses_correctly(self):
        """Tests that StdioMcpServer parses valid data."""
        # Arrange
        data = {
            "command": "/usr/bin/python",
            "args": ["-m", "my_module"],
            "cwd": "/tmp",
            "env": {"PYTHONPATH": "."},
        }

        # Act
        server = StdioMcpServer(**data)

        # Assert
        assert server.type == TransportType.stdio
        assert server.command == "/usr/bin/python"
        assert server.args == ["-m", "my_module"]
        assert server.cwd == Path("/tmp")
        assert server.env == {"PYTHONPATH": "."}

    def test_sse_mcp_server__with_valid_data__parses_correctly(self):
        """Tests that SseMcpServer parses valid data."""
        # Arrange
        data = {
            "url": "http://localhost:8080/sse  ",  # with whitespace
            "headers": {"Authorization": "Bearer token "},
            "timeout": 60.0,
        }

        # Act
        server = SseMcpServer(**data)

        # Assert
        assert server.type == TransportType.sse
        assert server.url == "http://localhost:8080/sse"
        assert server.headers == {"Authorization": "Bearer token"}
        assert server.timeout == 60.0

    def test_http_mcp_server__with_valid_data__parses_correctly(self):
        """Tests that HttpMcpServer parses valid data."""
        # Arrange
        data = {
            "url": "http://localhost:8080/stream",
            "terminate_on_close": True,
        }

        # Act
        server = HttpMcpServer(**data)

        # Assert
        assert server.type == TransportType.http
        assert server.url == "http://localhost:8080/stream"
        assert server.terminate_on_close is True

    def test_http_mcp_server_base__model_post_init__infers_type(self):
        """Tests that the server type is inferred from the URL if not provided."""
        # Arrange
        sse_server = SseMcpServer(url="http://foo.com/events/sse")
        http_server = HttpMcpServer(url="http://foo.com/api/stream")

        # Assert
        assert sse_server.type == TransportType.sse
        assert http_server.type == TransportType.http


class TestConfig:
    """Tests for the main Config Pydantic model."""

    def test_config__with_empty_data__creates_default_config(self):
        """Tests that an empty Config object has a default mcp_relay config."""
        # Arrange & Act
        config = Config()

        # Assert
        assert isinstance(config.mcp_relay, McpRelayConfig)
        assert config.mcp_servers == {}

    def test_config__with_full_data__parses_correctly(self):
        """Tests parsing of a full configuration structure."""
        # Arrange
        data = {
            "mcpRelay": {
                "apiKey": "my-key",
                "maxMcpServers": 2,
            },
            "mcpServers": {
                "server1": {
                    "type": "stdio",
                    "command": "cmd1",
                },
                "server2": {
                    "type": "sse",
                    "url": "http://server2/sse",
                },
            },
        }

        # Act
        config = Config(**data)

        # Assert
        assert config.mcp_relay.api_key.get_secret_value() == "my-key"
        assert config.mcp_relay.max_mcp_servers == 2
        assert len(config.mcp_servers) == 2
        assert isinstance(config.mcp_servers["server1"], StdioMcpServer)
        assert config.mcp_servers["server1"].command == "cmd1"
        assert isinstance(config.mcp_servers["server2"], SseMcpServer)
        assert config.mcp_servers["server2"].url == "http://server2/sse"

    def test_config__with_discriminated_union__parses_server_types_correctly(self):
        """Tests that server types are correctly discriminated without an explicit 'type' field."""
        # Arrange
        data = {
            "mcpRelay": {"maxMcpServers": 3},
            "mcpServers": {
                "stdio_server": {"command": "my_command"},
                "sse_server": {"url": "http://my.sse.server/sse"},
                "http_server": {"url": "http://my.http.server/stream"},
            },
        }

        # Act
        config = Config(**data)

        # Assert
        assert isinstance(config.mcp_servers["stdio_server"], StdioMcpServer)
        assert config.mcp_servers["stdio_server"].type == TransportType.stdio
        assert isinstance(config.mcp_servers["sse_server"], SseMcpServer)
        assert config.mcp_servers["sse_server"].type == TransportType.sse
        assert isinstance(config.mcp_servers["http_server"], HttpMcpServer)
        assert config.mcp_servers["http_server"].type == TransportType.http

    def test_config__model_post_init__when_too_many_servers__raises_error(self):
        """Tests that McpRelayConfigurationError is raised if server count exceeds the limit."""
        # Arrange
        data = {
            "mcpRelay": {
                "maxMcpServers": 1,
            },
            "mcpServers": {
                "server1": {"command": "cmd1"},
                "server2": {"command": "cmd2"},
            },
        }

        # Act & Assert
        with pytest.raises(McpRelayConfigurationError, match="Too many MCP servers"):
            Config(**data)
