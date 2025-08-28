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

"""Unit tests for pan_security_relay.py"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import mcp.types as types
import pytest

from pan_mcp_relay.exceptions import (
    McpRelayConfigurationError,
    McpRelaySecurityBlockError,
    McpRelayToolNotFoundError,
)
from pan_mcp_relay.pan_security_relay import PanSecurityRelay
from pan_mcp_relay.tool import InternalTool, ToolState


@pytest.fixture
def mock_config():
    """Fixture for McpRelayConfig."""
    config = MagicMock()
    config.max_mcp_servers = 10
    config.max_mcp_tools = 100
    return config


@pytest.fixture
def mock_mcp_servers_config():
    """Fixture for mcp_servers_config."""
    return {"server1": MagicMock()}


@pytest.fixture
@patch("pan_mcp_relay.pan_security_relay.RelaySessionGroup", new_callable=MagicMock)
@patch("pan_mcp_relay.pan_security_relay.SecurityScanner", new_callable=MagicMock)
@patch("pan_mcp_relay.pan_security_relay.ToolRegistry", new_callable=MagicMock)
def relay(mock_tool_registry, mock_security_scanner, mock_session_group, mock_config, mock_mcp_servers_config):
    """Fixture for PanSecurityRelay instance."""
    relay_instance = PanSecurityRelay(mock_config, mock_mcp_servers_config)
    relay_instance.tool_registry = mock_tool_registry
    relay_instance.scanner = mock_security_scanner
    relay_instance._client_session_group = mock_session_group
    return relay_instance


class TestPanSecurityRelay:
    """Test suite for PanSecurityRelay."""

    def test_init_success(self, mock_config, mock_mcp_servers_config):
        """Test successful initialization."""
        with (
            patch("pan_mcp_relay.pan_security_relay.RelaySessionGroup"),
            patch("pan_mcp_relay.pan_security_relay.SecurityScanner"),
            patch("pan_mcp_relay.pan_security_relay.ToolRegistry"),
        ):
            relay = PanSecurityRelay(mock_config, mock_mcp_servers_config)
            assert relay.config == mock_config
            assert relay.mcp_servers_config == mock_mcp_servers_config

    def test_init_no_mcp_servers(self, mock_config):
        """Test initialization with no MCP servers."""
        with pytest.raises(McpRelayConfigurationError, match=r"No MCP servers configured."):
            with (
                patch("pan_mcp_relay.pan_security_relay.RelaySessionGroup"),
                patch("pan_mcp_relay.pan_security_relay.SecurityScanner"),
                patch("pan_mcp_relay.pan_security_relay.ToolRegistry"),
            ):
                PanSecurityRelay(mock_config, {})

    def test_init_too_many_mcp_servers(self, mock_config):
        """Test initialization with too many MCP servers."""
        mock_config.max_mcp_servers = 1
        servers_config = {"server1": MagicMock(), "server2": MagicMock()}
        with pytest.raises(McpRelayConfigurationError, match="MCP servers configuration limit exceeded"):
            with (
                patch("pan_mcp_relay.pan_security_relay.RelaySessionGroup"),
                patch("pan_mcp_relay.pan_security_relay.SecurityScanner"),
                patch("pan_mcp_relay.pan_security_relay.ToolRegistry"),
            ):
                PanSecurityRelay(mock_config, servers_config)

    @pytest.mark.asyncio
    async def test_initialize(self, relay):
        """Test the _initialize method."""
        relay._update_tool_registry = AsyncMock()
        await relay._initialize()
        relay._update_tool_registry.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_shutdown(self, relay):
        """Test the shutdown method."""
        relay.scanner.shutdown = AsyncMock()
        relay._exit_stack.aclose = AsyncMock()

        await relay.shutdown()

        relay.scanner.shutdown.assert_awaited_once()
        relay._exit_stack.aclose.assert_awaited_once()

        # Test shutdown lock
        relay.scanner.shutdown.reset_mock()
        relay._exit_stack.aclose.reset_mock()
        async with asyncio.Lock():  # Simulate lock being held
            await relay.shutdown()
            relay.scanner.shutdown.assert_not_awaited()
            relay._exit_stack.aclose.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_list_tools_registry_updated(self, relay):
        """Test _list_tools when tool registry is up to date."""
        relay.tool_registry.is_registry_outdated.return_value = False
        mock_tool = InternalTool(
            name="test_tool",
            description="A test tool",
            state=ToolState.ENABLED,
            server_name="server1",
            arguments={},
        )
        relay.tool_registry.get_available_tools.return_value = {"test_tool": mock_tool}

        tools = await relay._list_tools()

        assert len(tools) == 1
        assert tools[0].name == "test_tool"
        relay.tool_registry.is_registry_outdated.assert_called_once()
        relay.tool_registry.get_available_tools.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_tools_registry_outdated(self, relay):
        """Test _list_tools when tool registry is outdated."""
        relay.tool_registry.is_registry_outdated.return_value = True
        relay._update_tool_registry = AsyncMock()
        mock_tool = InternalTool(
            name="test_tool",
            description="A test tool",
            state=ToolState.ENABLED,
            server_name="server1",
            arguments={},
        )
        relay.tool_registry.get_available_tools.return_value = {"test_tool": mock_tool}

        await relay._list_tools()

        relay.tool_registry.is_registry_outdated.assert_called_once()
        relay._update_tool_registry.assert_awaited_once()
        relay.tool_registry.get_available_tools.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_tool_success(self, relay):
        """Test a successful tool call."""
        tool_name = "test_tool"
        tool_args = {"arg1": "value1"}
        mock_tool = InternalTool(
            name=tool_name,
            description="A test tool",
            state=ToolState.ENABLED,
            server_name="server1",
            arguments={},
        )
        relay.tool_registry.get_available_tools.return_value = {tool_name: mock_tool}
        relay.scanner.scan = AsyncMock()
        mock_result = types.CallToolResult(content=[types.TextContent(text="Success")])
        relay._client_session_group.call_tool = AsyncMock(return_value=mock_result)

        result = await relay._call_tool(tool_name, tool_args)

        assert not result.isError
        assert result.content[0].text == "Success"
        relay.scanner.scan.assert_awaited()
        relay._client_session_group.call_tool.assert_awaited_with(tool_name, tool_args)

    @pytest.mark.asyncio
    async def test_call_tool_not_found(self, relay):
        """Test calling a tool that does not exist."""
        relay.tool_registry.get_available_tools.return_value = {}
        relay.scanner.scan = AsyncMock()

        with pytest.raises(McpRelayToolNotFoundError, match="Unknown tool: non_existent_tool"):
            await relay._call_tool("non_existent_tool", {})

        relay.scanner.scan.assert_awaited()

    @pytest.mark.asyncio
    async def test_call_tool_security_block(self, relay):
        """Test a tool call blocked by security scan."""
        tool_name = "test_tool"
        tool_args = {"arg1": "value1"}
        relay.scanner.scan = AsyncMock(side_effect=McpRelaySecurityBlockError("Blocked"))

        with pytest.raises(McpRelaySecurityBlockError):
            await relay._call_tool(tool_name, tool_args)

        relay.scanner.scan.assert_awaited_once()

    def test_extract_text_content(self, relay):
        """Test the extract_text_content helper function."""
        assert relay.extract_text_content("simple string") == "simple string"
        assert relay.extract_text_content(types.TextContent(text="hello")) == """{"text":"hello","type":"text"}"""
        assert relay.extract_text_content([types.TextContent(text="hello")]) == """{"text":"hello","type":"text"}"""
        assert relay.extract_text_content([types.TextContent(text="hello"), types.TextContent(text="world")]) == [
            """{"text":"hello","type":"text"}""",
            """{"text":"world","type":"text"}""",
        ]
