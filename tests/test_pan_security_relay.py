# Copyright (c) 2025, Palo Alto Networks
#
# Licensed under the Polyform Internal Use License 1.0.0 (the "License");
# you may not use this file except in compliance with the License.

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import mcp.types as types
import pytest
from mcp.server.lowlevel import Server

from pan_mcp_relay.constants import (
    TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO,
)
from pan_mcp_relay.exceptions import (  # noqa
    McpRelayBaseError,
    McpRelayConfigurationError,
    McpRelayInternalError,
    McpRelaySecurityBlockError,
    McpRelayServerNotFoundError,
    McpRelayToolExecutionError,
    McpRelayToolNotFoundError,
    McpRelayToolRegistryError,
    McpRelayValidationError,
)
from pan_mcp_relay.pan_security_relay import PanSecurityRelay
from pan_mcp_relay.tool import InternalTool, ToolState


@pytest.fixture
async def relay():
    """Set up minimal test fixtures."""
    relay = PanSecurityRelay("/test/config.json", security_scanner_env={})
    yield relay

    # Cleanup after each test
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


@pytest.fixture
def valid_config():
    """Valid configuration for testing."""
    return {"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}}


# ===================== Initialization Tests =====================


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._update_tool_registry", new_callable=AsyncMock)
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._update_security_scanner", new_callable=AsyncMock)
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._load_config", autospec=True)
async def test_initialize_success(
    mock_load_config, mock_update_security_scanner, mock_update_tool_registry, relay, valid_config
):
    """Test successful initialization flow."""
    mock_load_config.return_value = valid_config["mcpServers"]
    mock_update_security_scanner.return_value = None
    mock_update_tool_registry.return_value = None

    await relay._initialize()

    mock_load_config.assert_called_once()
    mock_update_security_scanner.assert_called_once()
    mock_update_tool_registry.assert_called_once()


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._load_config", autospec=True)
async def test_initialize_config_load_failure(mock_load_config, relay):
    """Test initialization failure when config loading fails."""
    mock_load_config.side_effect = McpRelayConfigurationError("Configuration file not found")

    with pytest.raises(McpRelayBaseError) as exc_info:
        await relay._initialize()

    assert isinstance(exc_info.value, McpRelayConfigurationError)
    assert "Configuration file not found" in str(exc_info.value)


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._load_config", autospec=True)
async def test_initialize_generic_exception_handling(mock_load_config, relay):
    """Test handling of generic exceptions during initialization."""
    mock_load_config.side_effect = ValueError("Unexpected error")

    with pytest.raises(ValueError) as exc_info:
        await relay._initialize()

    assert "Unexpected error" in str(exc_info.value)


# ===================== Configuration Management Tests =====================


@patch("pan_mcp_relay.configuration.Configuration.load_config", autospec=True)
def test_load_config_success(mock_load_config, relay, valid_config):
    """Test successful configuration loading."""
    mock_load_config.return_value = valid_config
    result = relay._load_config()
    assert result == valid_config["mcpServers"]


@patch("pan_mcp_relay.configuration.Configuration.load_config", autospec=True)
def test_load_config_file_not_found(mock_load_config, relay):
    """Test configuration loading when file is not found."""
    mock_load_config.side_effect = FileNotFoundError("No such file")

    with pytest.raises(McpRelayBaseError) as exc_info:
        relay._load_config()

    assert isinstance(exc_info.value, McpRelayConfigurationError)


@patch("pan_mcp_relay.configuration.Configuration.load_config", autospec=True)
def test_load_config_invalid_format(mock_load_config, relay):
    """Test configuration loading with invalid format."""
    mock_load_config.return_value = {"mcpServers": "invalid_format"}

    with pytest.raises(McpRelayBaseError) as exc_info:
        relay._load_config()

    assert "Unexpected configuration format" in str(exc_info.value)


@patch("pan_mcp_relay.configuration.Configuration.load_config", autospec=True)
def test_load_config_no_servers(mock_load_config, relay):
    """Test configuration loading with no servers configured."""
    mock_load_config.return_value = {"mcpServers": {}}

    with pytest.raises(McpRelayBaseError) as exc_info:
        relay._load_config()

    assert "No MCP servers configured" in str(exc_info.value)


@patch("pan_mcp_relay.configuration.Configuration.load_config", autospec=True)
def test_load_config_exceed_max_servers(mock_load_config):
    """Test configuration loading when exceeding maximum server limit."""
    large_config = {"mcpServers": {f"benign_server_{i}": {"command": "python"} for i in range(10)}}
    mock_load_config.return_value = large_config

    relay = PanSecurityRelay("/test/config.json", security_scanner_env={}, max_downstream_servers=2)

    with pytest.raises(McpRelayBaseError) as exc_info:
        relay._load_config()

    assert isinstance(exc_info.value, McpRelayConfigurationError)
    assert "MCP servers configuration limit exceeded" in str(exc_info.value)


# ===================== Security Scanner Tests =====================


@pytest.mark.asyncio
@patch("pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient.initialize", new_callable=AsyncMock)
@patch("pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient.cleanup", new_callable=AsyncMock)
@patch("pan_mcp_relay.security_scanner.SecurityScanner", autospec=True)
async def test_update_security_scanner_success(
    mock_security_scanner, mock_cleanup, mock_initialize, relay, valid_config
):
    """Test successful security scanner setup."""
    mock_initialize.return_value = None
    mock_cleanup.return_value = None
    mock_security_scanner.return_value = AsyncMock()

    await relay._initialize_security_scanner(valid_config["mcpServers"])

    assert relay.scanner is not None
    assert "pan-aisecurity" in relay.relay_clients


# ===================== Tool Management Tests =====================


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._disable_tools_with_duplicate_names", autospec=True)
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._validate_tool_limits", autospec=True)
@patch(
    "pan_mcp_relay.pan_security_relay.PanSecurityRelay._collect_tools_from_servers",
    new_callable=AsyncMock,
)
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._load_config", autospec=True)
async def test_update_tool_registry_success(
    mock_load_config, mock_collect_tools, mock_validate_limits, mock_disable_duplicates, relay, valid_config
):
    """Test successful tool registry update."""
    mock_load_config.return_value = valid_config["mcpServers"]
    benign_tools = [
        InternalTool(
            name="summarize_text_content",
            description="Summarize text content from documents",
            inputSchema={},
            annotations=None,
            server_name="benign_text_processor",
            state=ToolState.ENABLED,
        )
    ]
    mock_collect_tools.return_value = benign_tools

    relay.tool_registry = Mock()

    await relay._update_tool_registry()

    mock_collect_tools.assert_called_once()
    mock_validate_limits.assert_called_once()
    mock_disable_duplicates.assert_called_once()
    relay.tool_registry.update_registry.assert_called_once()


@pytest.mark.asyncio
@patch("pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient.cleanup", new_callable=AsyncMock)
@patch("pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient.list_tools", new_callable=AsyncMock)
@patch("pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient.initialize", new_callable=AsyncMock)
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._prepare_tool", new_callable=AsyncMock)
async def test_collect_tools_from_servers_success(
    mock_prepare_tool, mock_initialize, mock_list_tools, mock_cleanup, relay
):
    """Test successful collection of tools from multiple servers."""
    servers_config = {
        "benign_text_processor": {"command": "python", "args": ["/path/to/benign_text_processor.py"]},
        "benign_data_analyzer": {
            "command": "python",
            "args": ["/path/to/benign_data_analyzer.py"],
            "env": {"hidden_mode": "enabled"},
        },
    }

    text_processor_tools = [
        types.Tool(name="summarize_text_content", description="Summarize text content", inputSchema={})
    ]
    data_analyzer_tools = [
        types.Tool(name="analyze_data_patterns", description="Analyze data patterns", inputSchema={})
    ]

    mock_initialize.return_value = None
    mock_cleanup.return_value = None
    mock_list_tools.side_effect = [text_processor_tools, data_analyzer_tools]
    mock_prepare_tool.return_value = None

    await relay._initialize_relay_clients(servers_config)

    assert mock_initialize.call_count == 2
    assert mock_cleanup.call_count == 2
    assert mock_list_tools.call_count == 2
    assert mock_prepare_tool.call_count == 2

    assert "benign_text_processor" in relay.relay_clients
    assert "benign_data_analyzer" in relay.relay_clients

    mock_prepare_tool.assert_any_call("benign_text_processor", text_processor_tools, False, [])
    mock_prepare_tool.assert_any_call("benign_data_analyzer", data_analyzer_tools, True, [])


@pytest.mark.asyncio
@patch("pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient.cleanup", new_callable=AsyncMock)
@patch("pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient.list_tools", new_callable=AsyncMock)
@patch("pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient.initialize", new_callable=AsyncMock)
async def test_collect_tools_from_servers_initialization_failure(mock_initialize, mock_list_tools, mock_cleanup, relay):
    """Test collection of tools when server initialization fails."""
    servers_config = {"benign_text_processor": {"command": "python", "args": ["/path/to/benign_text_processor.py"]}}

    mock_initialize.side_effect = Exception("Server initialization failed")
    mock_cleanup.return_value = None

    with pytest.raises(Exception) as exc_info:
        await relay._initialize_relay_clients(servers_config)

    assert "Server initialization failed" in str(exc_info.value)
    mock_list_tools.assert_not_called()


@pytest.mark.asyncio
@patch("pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient.cleanup", new_callable=AsyncMock)
@patch("pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient.list_tools", new_callable=AsyncMock)
@patch("pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient.initialize", new_callable=AsyncMock)
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._prepare_tool", new_callable=AsyncMock)
async def test_collect_tools_from_servers_hidden_mode_detection(
    mock_prepare_tool, mock_initialize, mock_list_tools, mock_cleanup, relay
):
    """Test hidden mode detection in server configuration."""
    servers_config = {
        "benign_text_processor": {
            "command": "python",
            "args": ["/path/to/benign_text_processor.py"],
            "env": {"hidden_mode": "enabled"},
        },
        "benign_data_analyzer": {
            "command": "python",
            "args": ["/path/to/benign_data_analyzer.py"],
            "env": {"hidden_mode": "disabled"},
        },
        "benign_file_processor": {"command": "python", "args": ["/path/to/benign_file_processor.py"]},
    }

    mock_tools = [types.Tool(name="test_tool", description="Test tool", inputSchema={})]
    mock_initialize.return_value = None
    mock_cleanup.return_value = None
    mock_list_tools.return_value = mock_tools
    mock_prepare_tool.return_value = None

    await relay._initialize_relay_clients(servers_config)

    mock_prepare_tool.assert_any_call("benign_text_processor", mock_tools, True, [])  # hidden_mode enabled
    mock_prepare_tool.assert_any_call("benign_data_analyzer", mock_tools, False, [])  # hidden_mode disabled
    mock_prepare_tool.assert_any_call("benign_file_processor", mock_tools, False, [])  # no env config


def test_validate_tool_limits_success():
    """Test tool limits validation with acceptable number of tools."""
    max_tools = 5
    benign_tools = [
        InternalTool(
            name=f"text_processor_{i}",
            description="Process text content",
            inputSchema={},
            annotations=None,
            server_name="benign_text_processor",
            state=ToolState.ENABLED,
        )
        for i in range(max_tools - 1)
    ]

    relay = PanSecurityRelay("/test/config.json", security_scanner_env={}, max_downstream_tools=max_tools)

    relay._validate_tool_limits(benign_tools)


def test_validate_tool_limits_exceeded():
    """Test tool limits validation when exceeding maximum tools."""
    max_tools = 3
    benign_tools = [
        InternalTool(
            name=f"text_processor_{i}",
            description="Process text content",
            inputSchema={},
            annotations=None,
            server_name="benign_text_processor",
            state=ToolState.ENABLED,
        )
        for i in range(max_tools + 1)
    ]

    relay = PanSecurityRelay("/test/config.json", security_scanner_env={}, max_downstream_tools=max_tools)

    with pytest.raises(McpRelayBaseError) as exc_info:
        relay._validate_tool_limits(benign_tools)

    assert isinstance(exc_info.value, McpRelayConfigurationError)
    assert f"maximum allowed: {max_tools}" in str(exc_info.value)


@pytest.mark.asyncio
@patch("pan_mcp_relay.security_scanner.SecurityScanner.should_block")
@patch("pan_mcp_relay.security_scanner.SecurityScanner.scan_tool", new_callable=AsyncMock)
async def test_prepare_tool_benign_scan_result(mock_scan_tool, mock_should_block, relay):
    """Test tool preparation with benign security scan result."""
    benign_scan_result = {
        "action": "allow",
        "category": "benign",
        "profile_id": "ba51dae8-4675-4f89-8027-9adcc01e41e3",
        "profile_name": "MCP-Security",
        "prompt_detected": {"dlp": False, "injection": False, "url_cats": False},
        "report_id": "Rfed6481f-b349-44c0-b6cb-72a4219efbc6",
        "response_detected": {"dlp": False, "url_cats": False},
        "scan_id": "fed6481f-b349-44c0-b6cb-72a4219efbc6",
        "tr_id": "12348ba3396e",
    }

    relay.tool_registry = Mock()
    relay.tool_registry.get_tool_by_hash.return_value = None
    relay.scanner = Mock()
    relay.scanner.scan_tool = mock_scan_tool
    relay.scanner.should_block = mock_should_block

    mock_scan_tool.return_value = benign_scan_result
    mock_should_block.return_value = False

    benign_tool = types.Tool(
        name="summarize_text_content", description="Summarize text content from documents", inputSchema={}
    )
    tool_list = []

    await relay._scan_tool("benign_text_processor", [benign_tool], False, tool_list)

    assert len(tool_list) == 1
    assert tool_list[0].state == ToolState.ENABLED


@pytest.mark.asyncio
@patch("pan_mcp_relay.security_scanner.SecurityScanner.should_block")
@patch("pan_mcp_relay.security_scanner.SecurityScanner.scan_tool", new_callable=AsyncMock)
async def test_prepare_tool_malicious_scan_result(mock_scan_tool, mock_should_block, relay):
    """Test tool preparation with malicious security scan result."""
    malicious_scan_result = {
        "action": "block",
        "category": "malicious",
        "profile_id": "ba51dae8-4675-4f89-8027-9adcc01e41e3",
        "profile_name": "MCP-Security",
        "prompt_detected": {"dlp": False, "injection": True, "url_cats": False},
        "report_id": "R9b6ff47b-7dc2-4bab-97a7-67962c6c2c3e",
        "response_detected": {"dlp": False, "url_cats": False},
        "scan_id": "9b6ff47b-7dc2-4bab-97a7-67962c6c2c3e",
        "tr_id": "1234194a0101",
    }

    relay.tool_registry = Mock()
    relay.tool_registry.get_tool_by_hash.return_value = None
    relay.scanner = Mock()
    relay.scanner.scan_tool = mock_scan_tool
    relay.scanner.should_block = mock_should_block

    mock_scan_tool.return_value = malicious_scan_result
    mock_should_block.return_value = True

    malicious_tool = types.Tool(
        name="malicious_execute_system_command",
        description="Execute system commands with elevated privileges",
        inputSchema={},
    )
    tool_list = []

    await relay._scan_tool("malicious_command_executor", [malicious_tool], False, tool_list)

    assert len(tool_list) == 1
    assert tool_list[0].state == ToolState.DISABLED_SECURITY_RISK


@pytest.mark.asyncio
async def test_prepare_tool_hidden_mode(relay):
    """Test tool preparation in hidden mode."""
    pan_inline_scan_tool = types.Tool(
        name="pan_inline_scan", description="Palo Alto Networks inline security scanning", inputSchema={}
    )
    tool_list = []

    await relay._scan_tool("pan-aisecurity", [pan_inline_scan_tool], True, tool_list)

    assert len(tool_list) == 1
    assert tool_list[0].state == ToolState.DISABLED_HIDDEN_MODE


@pytest.mark.asyncio
async def test_prepare_tool_existing_tool_reuse_state(relay):
    """Test tool preparation when tool already exists in registry with cached state."""
    existing_tool = InternalTool(
        name="summarize_text_content",
        description="Summarize text content from documents",
        inputSchema={},
        annotations=None,
        server_name="previous_text_processor",
        state=ToolState.DISABLED_SECURITY_RISK,
    )

    relay.tool_registry = Mock()
    relay.tool_registry.get_tool_by_hash.return_value = existing_tool

    benign_tool = types.Tool(
        name="summarize_text_content", description="Summarize text content from documents", inputSchema={}
    )
    tool_list = []

    await relay._scan_tool("benign_text_processor", [benign_tool], False, tool_list)

    assert len(tool_list) == 1
    assert tool_list[0].state == ToolState.DISABLED_SECURITY_RISK
    assert tool_list[0].server_name == "benign_text_processor"

    relay.tool_registry.get_tool_by_hash.assert_called_once()


def test_disable_tools_with_duplicate_names(relay):
    """Test disabling tools with duplicate names."""
    tools = [
        InternalTool(
            name="network_ping",
            description="Network connectivity test",
            inputSchema={},
            annotations=None,
            server_name="benign_network_tools",
            state=ToolState.ENABLED,
        ),
        InternalTool(
            name="network_ping",
            description="Enhanced network ping utility",
            inputSchema={},
            annotations=None,
            server_name="benign_diagnostics",
            state=ToolState.ENABLED,
        ),
        InternalTool(
            name="text_summarizer",
            description="Summarize large text documents",
            inputSchema={},
            annotations=None,
            server_name="benign_text_processor",
            state=ToolState.ENABLED,
        ),
    ]

    relay._warn_tools_with_duplicate_names(tools)

    ping_tools = [tool for tool in tools if tool.name == "network_ping"]
    for ping_tool in ping_tools:
        assert ping_tool.state == ToolState.DISABLED_DUPLICATE

    unique_tool = next(tool for tool in tools if tool.name == "text_summarizer")
    assert unique_tool.state == ToolState.ENABLED


# ===================== MCP Server Handling Tests =====================


@pytest.mark.asyncio
async def test_launch_mcp_server_success(relay):
    """Test successful MCP server creation."""
    server = await relay.mcp_server()

    assert server is not None
    assert isinstance(server, Server)


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.stdio_server", autospec=True)
async def test_run_stdio_server_success(mock_stdio_server, relay):
    """Test successful stdio server startup."""
    # Mock the stdio server context manager
    mock_streams = (AsyncMock(), AsyncMock())
    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_streams
    mock_context_manager.__aexit__.return_value = None
    mock_stdio_server.return_value = mock_context_manager

    mock_app = AsyncMock()
    mock_app.run = AsyncMock()
    mock_app.create_initialization_options = Mock(return_value={"test": "options"})

    await relay.run_stdio_server(mock_app)

    mock_stdio_server.assert_called_once()

    mock_context_manager.__aenter__.assert_called_once()
    mock_context_manager.__aexit__.assert_called_once()

    mock_app.run.assert_called_once_with(mock_streams[0], mock_streams[1], {"test": "options"})
    mock_app.create_initialization_options.assert_called_once()


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.stdio_server", autospec=True)
async def test_run_stdio_server_initialization_failure(mock_stdio_server, relay):
    """Test stdio server startup with initialization failure."""
    mock_stdio_server.side_effect = Exception("Stdio server initialization failed")

    mock_app = AsyncMock()

    with pytest.raises(Exception) as exc_info:
        await relay.run_stdio_server(mock_app)

    assert "Stdio server initialization failed" in str(exc_info.value)
    mock_stdio_server.assert_called_once()


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.stdio_server", autospec=True)
async def test_run_stdio_server_app_run_failure(mock_stdio_server, relay):
    """Test stdio server startup with app run failure."""
    mock_streams = (AsyncMock(), AsyncMock())
    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_streams
    mock_context_manager.__aexit__.return_value = None
    mock_stdio_server.return_value = mock_context_manager

    mock_app = AsyncMock()
    mock_app.run.side_effect = Exception("App run failed")
    mock_app.create_initialization_options = Mock(return_value={})

    with pytest.raises(Exception) as exc_info:
        await relay.run_stdio_server(mock_app)

    assert "App run failed" in str(exc_info.value)
    mock_app.run.assert_called_once()


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.uvicorn.Server", autospec=True)
@patch("pan_mcp_relay.pan_security_relay.uvicorn.Config", autospec=True)
@patch("pan_mcp_relay.pan_security_relay.Starlette", autospec=True)
@patch("pan_mcp_relay.pan_security_relay.Route", autospec=True)
@patch("pan_mcp_relay.pan_security_relay.MessagesEndpoint", autospec=True)
@patch("pan_mcp_relay.pan_security_relay.SseEndpoint", autospec=True)
@patch("pan_mcp_relay.pan_security_relay.SseServerTransport", autospec=True)
async def test_run_sse_server_success(
    mock_sse_transport,
    mock_sse_endpoint,
    mock_messages_endpoint,
    mock_route,
    mock_starlette,
    mock_uvicorn_config,
    mock_uvicorn_server,
    relay,
):
    """Test successful SSE server startup."""
    mock_transport_instance = AsyncMock()
    mock_sse_transport.return_value = mock_transport_instance

    mock_sse_endpoint_instance = AsyncMock()
    mock_sse_endpoint.return_value = mock_sse_endpoint_instance

    mock_messages_endpoint_instance = AsyncMock()
    mock_messages_endpoint.return_value = mock_messages_endpoint_instance

    mock_route_instances = [AsyncMock(), AsyncMock()]
    mock_route.side_effect = mock_route_instances

    mock_starlette_app = AsyncMock()
    mock_starlette.return_value = mock_starlette_app

    mock_config_instance = AsyncMock()
    mock_uvicorn_config.return_value = mock_config_instance

    mock_server_instance = AsyncMock()
    mock_server_instance.serve = AsyncMock()
    mock_uvicorn_server.return_value = mock_server_instance

    mock_app = AsyncMock()

    await relay.run_sse_server(mock_app, "127.0.0.1", 8000)

    mock_sse_transport.assert_called_once_with("/messages")

    mock_sse_endpoint.assert_called_once_with(mock_transport_instance, mock_app)
    mock_messages_endpoint.assert_called_once_with(mock_transport_instance)

    assert mock_route.call_count == 2
    mock_route.assert_any_call("/sse", endpoint=mock_sse_endpoint_instance)
    mock_route.assert_any_call("/messages", endpoint=mock_messages_endpoint_instance, methods=["POST"])

    mock_starlette.assert_called_once_with(routes=mock_route_instances)

    mock_uvicorn_config.assert_called_once_with(mock_starlette_app, host="127.0.0.1", port=8000)
    mock_uvicorn_server.assert_called_once_with(mock_config_instance)
    mock_server_instance.serve.assert_called_once()


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.uvicorn.Server", autospec=True)
@patch("pan_mcp_relay.pan_security_relay.uvicorn.Config", autospec=True)
@patch("pan_mcp_relay.pan_security_relay.Starlette", autospec=True)
@patch("pan_mcp_relay.pan_security_relay.SseServerTransport", autospec=True)
async def test_run_sse_server_uvicorn_failure(
    mock_sse_transport, mock_starlette, mock_uvicorn_config, mock_uvicorn_server, relay
):
    """Test SSE server startup with uvicorn server failure."""
    mock_sse_transport.return_value = AsyncMock()
    mock_starlette.return_value = AsyncMock()
    mock_uvicorn_config.return_value = AsyncMock()

    mock_server_instance = AsyncMock()
    mock_server_instance.serve.side_effect = Exception("Uvicorn server startup failed")
    mock_uvicorn_server.return_value = mock_server_instance

    mock_app = AsyncMock()

    with pytest.raises(Exception) as exc_info:
        await relay.run_sse_server(mock_app, "127.0.0.1", 8000)

    assert "Uvicorn server startup failed" in str(exc_info.value)
    mock_server_instance.serve.assert_called_once()


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.Starlette", autospec=True)
@patch("pan_mcp_relay.pan_security_relay.SseServerTransport", autospec=True)
async def test_run_sse_server_starlette_failure(mock_sse_transport, mock_starlette, relay):
    """Test SSE server startup with Starlette app creation failure."""
    mock_sse_transport.return_value = AsyncMock()

    mock_starlette.side_effect = Exception("Starlette app creation failed")

    mock_app = AsyncMock()

    with pytest.raises(Exception) as exc_info:
        await relay.run_sse_server(mock_app, "127.0.0.1", 8000)

    assert "Starlette app creation failed" in str(exc_info.value)
    mock_starlette.assert_called_once()


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._update_tool_registry", new_callable=AsyncMock)
async def test_handle_list_tools_up_to_date_registry(mock_update_tool_registry, relay):
    """Test tool listing with up-to-date registry."""
    relay.tool_registry = Mock()
    benign_tools = [
        InternalTool(
            name="summarize_text_content",
            description="Summarize text content from documents",
            inputSchema={},
            annotations=None,
            server_name="benign_text_processor",
            state=ToolState.ENABLED,
        )
    ]
    relay.tool_registry.get_available_tools.return_value = benign_tools
    relay.tool_registry.is_registry_outdated.return_value = False

    result = await relay._list_tools()

    assert len(result) == 2
    tool_names = [tool.name for tool in result]
    assert "summarize_text_content" in tool_names
    assert TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO in tool_names
    mock_update_tool_registry.assert_not_called()


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._update_tool_registry", new_callable=AsyncMock)
async def test_handle_list_tools_outdated_registry(mock_update_tool_registry, relay):
    """Test tool listing with outdated registry."""
    relay.tool_registry = Mock()
    benign_tools = [
        InternalTool(
            name="summarize_text_content",
            description="Summarize text content from documents",
            inputSchema={},
            annotations=None,
            server_name="benign_text_processor",
            state=ToolState.ENABLED,
        )
    ]
    relay.tool_registry.get_available_tools.return_value = benign_tools
    relay.tool_registry.is_registry_outdated.return_value = True

    await relay._list_tools()

    mock_update_tool_registry.assert_called_once()


# ===================== Tool Execution Tests =====================


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._execute_on_server", new_callable=AsyncMock)
@patch("pan_mcp_relay.security_scanner.SecurityScanner.should_block")
@patch("pan_mcp_relay.security_scanner.SecurityScanner.scan_response", new_callable=AsyncMock)
@patch("pan_mcp_relay.security_scanner.SecurityScanner.scan_request", new_callable=AsyncMock)
async def test_handle_tool_execution_success(
    mock_scan_request, mock_scan_response, mock_should_block, mock_execute_on_server, relay
):
    """Test successful tool execution without security blocks."""
    benign_scan_result = {
        "action": "allow",
        "category": "benign",
        "profile_id": "ba51dae8-4675-4f89-8027-9adcc01e41e3",
        "profile_name": "MCP-Security",
        "prompt_detected": {"dlp": False, "injection": False, "url_cats": False},
        "report_id": "Rfed6481f-b349-44c0-b6cb-72a4219efbc6",
        "response_detected": {"dlp": False, "url_cats": False},
        "scan_id": "fed6481f-b349-44c0-b6cb-72a4219efbc6",
        "tr_id": "12348ba3396e",
    }

    mock_scan_request.return_value = benign_scan_result
    mock_scan_response.return_value = benign_scan_result
    mock_should_block.return_value = False
    mock_execute_on_server.return_value = types.CallToolResult(
        content=[types.TextContent(type="text", text="Text successfully summarized.")], isError=False
    )

    relay.tool_registry = Mock()
    relay.tool_registry.get_available_tools.return_value = [
        InternalTool(
            name="summarize_text_content",
            description="Summarize text content from documents",
            inputSchema={},
            annotations=None,
            server_name="benign_text_processor",
            state=ToolState.ENABLED,
        )
    ]
    relay.scanner = Mock()
    relay.scanner.scan_request = mock_scan_request
    relay.scanner.scan_response = mock_scan_response
    relay.scanner.should_block = mock_should_block
    relay.scanner.pan_security_server = Mock()
    relay.scanner.pan_security_server.extract_text_content.return_value = "Text successfully summarized."

    result = await relay._call_tool("summarize_text_content", {"text": "Sample document content to summarize"})

    assert isinstance(result, types.CallToolResult)
    assert not result.isError


@pytest.mark.asyncio
@patch("pan_mcp_relay.security_scanner.SecurityScanner.should_block")
@patch("pan_mcp_relay.security_scanner.SecurityScanner.scan_request", new_callable=AsyncMock)
async def test_handle_tool_execution_request_blocked(mock_scan_request, mock_should_block, relay):
    """Test tool execution blocked by security scan on request."""
    malicious_scan_result = {
        "action": "block",
        "category": "malicious",
        "profile_id": "ba51dae8-4675-4f89-8027-9adcc01e41e3",
        "profile_name": "MCP-Security",
        "prompt_detected": {"dlp": False, "injection": True, "url_cats": False},
        "report_id": "R9b6ff47b-7dc2-4bab-97a7-67962c6c2c3e",
        "response_detected": {"dlp": False, "url_cats": False},
        "scan_id": "9b6ff47b-7dc2-4bab-97a7-67962c6c2c3e",
        "tr_id": "1234194a0101",
    }

    mock_scan_request.return_value = malicious_scan_result
    mock_should_block.return_value = True

    relay.tool_registry = Mock()
    relay.tool_registry.get_available_tools.return_value = [
        InternalTool(
            name="execute_system_command",
            description="Execute system commands",
            inputSchema={},
            annotations=None,
            server_name="malicious_command_executor",
            state=ToolState.ENABLED,
        )
    ]
    relay.scanner = Mock()
    relay.scanner.scan_request = mock_scan_request
    relay.scanner.should_block = mock_should_block

    with pytest.raises(McpRelayBaseError) as exc_info:
        await relay._call_tool("execute_system_command", {"command": "rm -rf /"})

    assert isinstance(exc_info.value, McpRelaySecurityBlockError)
    assert "Unsafe Request" in str(exc_info.value)


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._execute_on_server", new_callable=AsyncMock)
@patch("pan_mcp_relay.security_scanner.SecurityScanner.should_block")
@patch("pan_mcp_relay.security_scanner.SecurityScanner.scan_response", new_callable=AsyncMock)
@patch("pan_mcp_relay.security_scanner.SecurityScanner.scan_request", new_callable=AsyncMock)
async def test_handle_tool_execution_response_blocked(
    mock_scan_request, mock_scan_response, mock_should_block, mock_execute_on_server, relay
):
    """Test tool execution blocked by security scan on response."""
    benign_request_scan_result = {
        "action": "allow",
        "category": "benign",
        "profile_id": "ba51dae8-4675-4f89-8027-9adcc01e41e3",
        "profile_name": "MCP-Security",
        "prompt_detected": {"dlp": False, "injection": False, "url_cats": False},
        "report_id": "Rfed6481f-b349-44c0-b6cb-72a4219efbc6",
        "response_detected": {"dlp": False, "url_cats": False},
        "scan_id": "fed6481f-b349-44c0-b6cb-72a4219efbc6",
        "tr_id": "12348ba3396e",
    }

    malicious_response_scan_result = {
        "action": "block",
        "category": "malicious",
        "profile_id": "ba51dae8-4675-4f89-8027-9adcc01e41e3",
        "profile_name": "MCP-Security",
        "prompt_detected": {"dlp": False, "injection": False, "url_cats": False},
        "report_id": "R9b6ff47b-7dc2-4bab-97a7-67962c6c2c3e",
        "response_detected": {"dlp": False, "url_cats": True},
        "scan_id": "9b6ff47b-7dc2-4bab-97a7-67962c6c2c3e",
        "tr_id": "1234194a0101",
    }

    mock_scan_request.return_value = benign_request_scan_result
    mock_scan_response.return_value = malicious_response_scan_result
    mock_should_block.side_effect = [False, True]
    mock_execute_on_server.return_value = types.CallToolResult(
        content=[types.TextContent(type="text", text="Malicious content detected in response")], isError=False
    )

    relay.tool_registry = Mock()
    relay.tool_registry.get_available_tools.return_value = [
        InternalTool(
            name="web_content_fetcher",
            description="Fetch content from web URLs",
            inputSchema={},
            annotations=None,
            server_name="benign_web_tools",
            state=ToolState.ENABLED,
        )
    ]
    relay.scanner = Mock()
    relay.scanner.scan_request = mock_scan_request
    relay.scanner.scan_response = mock_scan_response
    relay.scanner.should_block = mock_should_block
    relay.scanner.pan_security_server = Mock()
    relay.scanner.pan_security_server.extract_text_content.return_value = "Malicious content detected in response"

    with pytest.raises(McpRelayBaseError) as exc_info:
        await relay._call_tool(
            "web_content_fetcher", {"url": "https://urlfiltering.paloaltonetworks.com/test-phishing"}
        )

    assert isinstance(exc_info.value, McpRelaySecurityBlockError)
    assert "Unsafe Response" in str(exc_info.value)


@pytest.mark.asyncio
async def test_handle_tool_execution_tool_not_found(relay):
    """Test tool execution with non-existent tool."""
    relay.scanner = Mock()
    relay.scanner.scan_request = AsyncMock(return_value={"category": "benign"})
    relay.scanner.should_block.return_value = False
    relay.tool_registry = Mock()
    relay.tool_registry.get_available_tools.return_value = []

    with pytest.raises(McpRelayBaseError) as exc_info:
        await relay._call_tool("nonexistent_tool", {})

    assert isinstance(exc_info.value, McpRelayToolNotFoundError)


@pytest.mark.asyncio
async def test_handle_tool_execution_empty_tool_name(relay):
    """Test tool execution with empty tool name."""
    relay.scanner = Mock()
    relay.scanner.scan_request = AsyncMock(return_value={"category": "benign"})
    relay.scanner.should_block.return_value = False
    relay.tool_registry = Mock()
    relay.tool_registry.get_available_tools.return_value = []

    with pytest.raises(McpRelayBaseError) as exc_info:
        await relay._call_tool("", {})

    assert isinstance(exc_info.value, McpRelayToolNotFoundError)


@pytest.mark.asyncio
async def test_handle_tool_execution_empty_arguments(relay):
    """Test tool execution with empty arguments."""
    benign_scan_result = {
        "action": "allow",
        "category": "benign",
        "profile_id": "ba51dae8-4675-4f89-8027-9adcc01e41e3",
        "profile_name": "MCP-Security",
        "prompt_detected": {"dlp": False, "injection": False, "url_cats": False},
        "report_id": "Rfed6481f-b349-44c0-b6cb-72a4219efbc6",
        "response_detected": {"dlp": False, "url_cats": False},
        "scan_id": "fed6481f-b349-44c0-b6cb-72a4219efbc6",
        "tr_id": "12348ba3396e",
    }

    relay.tool_registry = Mock()
    relay.tool_registry.get_available_tools.return_value = [
        InternalTool(
            name="summarize_text_content",
            description="Summarize text content",
            inputSchema={},
            annotations=None,
            server_name="benign_text_processor",
            state=ToolState.ENABLED,
        )
    ]
    relay.scanner = Mock()
    relay.scanner.scan_request = AsyncMock(return_value=benign_scan_result)
    relay.scanner.scan_response = AsyncMock(return_value=benign_scan_result)
    relay.scanner.should_block.return_value = False
    relay.scanner.pan_security_server = Mock()
    relay.scanner.pan_security_server.extract_text_content.return_value = "Success"

    with patch.object(relay, "_execute_on_server", new_callable=AsyncMock) as mock_execute:
        mock_execute.return_value = types.CallToolResult(
            content=[types.TextContent(type="text", text="Success")], isError=False
        )

        result = await relay._call_tool("summarize_text_content", {})

        assert isinstance(result, types.CallToolResult)
        mock_execute.assert_called_once_with("benign_text_processor", "summarize_text_content", {})


@pytest.mark.asyncio
@patch(
    "pan_mcp_relay.pan_security_relay.PanSecurityRelay._handle_list_downstream_servers_info",
    new_callable=AsyncMock,
)
@patch("pan_mcp_relay.security_scanner.SecurityScanner.should_block")
@patch("pan_mcp_relay.security_scanner.SecurityScanner.scan_request", new_callable=AsyncMock)
async def test_handle_tool_execution_special_relay_info_tool(
    mock_scan_request, mock_should_block, mock_handle_relay_info, relay
):
    """Test tool execution for the special relay info tool."""
    benign_scan_result = {
        "action": "allow",
        "category": "benign",
        "profile_id": "ba51dae8-4675-4f89-8027-9adcc01e41e3",
        "profile_name": "MCP-Security",
        "prompt_detected": {"dlp": False, "injection": False, "url_cats": False},
        "report_id": "Rfed6481f-b349-44c0-b6cb-72a4219efbc6",
        "response_detected": {"dlp": False, "url_cats": False},
        "scan_id": "fed6481f-b349-44c0-b6cb-72a4219efbc6",
        "tr_id": "12348ba3396e",
    }

    expected_result = types.CallToolResult(
        content=[
            types.TextContent(type="text", text='{"servers": {"benign_text_processor": ["summarize_text_content"]}}')
        ],
        isError=False,
    )

    mock_scan_request.return_value = benign_scan_result
    mock_should_block.return_value = False
    mock_handle_relay_info.return_value = expected_result

    relay.scanner = Mock()
    relay.scanner.scan_request = mock_scan_request
    relay.scanner.should_block = mock_should_block

    result = await relay._call_tool(TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO, {})

    assert isinstance(result, types.CallToolResult)
    assert not result.isError
    mock_handle_relay_info.assert_called_once()
    mock_scan_request.assert_called_once_with(f"{TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO}: {{}}")


@pytest.mark.asyncio
@patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._execute_on_server", new_callable=AsyncMock)
@patch("pan_mcp_relay.security_scanner.SecurityScanner.should_block")
@patch("pan_mcp_relay.security_scanner.SecurityScanner.scan_response", new_callable=AsyncMock)
@patch("pan_mcp_relay.security_scanner.SecurityScanner.scan_request", new_callable=AsyncMock)
async def test_handle_tool_execution_server_returns_error(
    mock_scan_request, mock_scan_response, mock_should_block, mock_execute_on_server, relay
):
    """Test tool execution when downstream server returns an error result."""
    benign_scan_result = {
        "action": "allow",
        "category": "benign",
        "profile_id": "ba51dae8-4675-4f89-8027-9adcc01e41e3",
        "profile_name": "MCP-Security",
        "prompt_detected": {"dlp": False, "injection": False, "url_cats": False},
        "report_id": "Rfed6481f-b349-44c0-b6cb-72a4219efbc6",
        "response_detected": {"dlp": False, "url_cats": False},
        "scan_id": "fed6481f-b349-44c0-b6cb-72a4219efbc6",
        "tr_id": "12348ba3396e",
    }

    mock_scan_request.return_value = benign_scan_result
    mock_scan_response.return_value = benign_scan_result
    mock_should_block.return_value = False
    mock_execute_on_server.return_value = types.CallToolResult(
        content=[types.TextContent(type="text", text="Tool execution failed on downstream server")], isError=True
    )

    relay.tool_registry = Mock()
    relay.tool_registry.get_available_tools.return_value = [
        InternalTool(
            name="summarize_text_content",
            description="Summarize text content from documents",
            inputSchema={},
            annotations=None,
            server_name="benign_text_processor",
            state=ToolState.ENABLED,
        )
    ]
    relay.scanner = Mock()
    relay.scanner.scan_request = mock_scan_request
    relay.scanner.scan_response = mock_scan_response
    relay.scanner.should_block = mock_should_block
    relay.scanner.pan_security_server = Mock()
    relay.scanner.pan_security_server.extract_text_content.return_value = "Tool execution failed on downstream server"

    with pytest.raises(McpRelayBaseError) as exc_info:
        await relay._call_tool("summarize_text_content", {"text": "Sample document content"})

    assert isinstance(exc_info.value, McpRelayToolExecutionError)
    mock_execute_on_server.assert_called_once_with(
        "benign_text_processor", "summarize_text_content", {"text": "Sample document content"}
    )


# ===================== Server Execution Tests =====================


@pytest.mark.asyncio
async def test_execute_on_server_success(relay):
    """Test successful server execution."""
    success_result = types.CallToolResult(
        content=[types.TextContent(type="text", text="Text processing completed successfully")], isError=False
    )

    mock_server = AsyncMock()
    mock_server.execute_tool.return_value = success_result
    relay.relay_clients["benign_text_processor"] = mock_server

    result = await relay._execute_on_server(
        "benign_text_processor", "summarize_text_content", {"text": "Sample content"}
    )
    assert result == success_result


@pytest.mark.asyncio
async def test_execute_on_server_not_found(relay):
    """Test server execution with non-existent server."""
    with pytest.raises(McpRelayBaseError) as exc_info:
        await relay._execute_on_server("nonexistent_server", "summarize_text_content", {})

    assert isinstance(exc_info.value, McpRelayServerNotFoundError)


@pytest.mark.asyncio
async def test_execute_on_server_execution_error(relay):
    """Test server execution with tool execution error."""
    mock_server = AsyncMock()
    mock_server.execute_tool.side_effect = Exception("Tool execution failed")
    relay.relay_clients["benign_text_processor"] = mock_server

    with pytest.raises(Exception) as exc_info:
        await relay._execute_on_server("benign_text_processor", "summarize_text_content", {})

    assert "Tool execution failed" in str(exc_info.value)


# ===================== Special Tools Tests =====================


@pytest.mark.asyncio
async def test_handle_list_downstream_servers_info_success(relay):
    """Test handling of the special downstream servers info tool."""
    relay.tool_registry = Mock()
    relay.tool_registry.get_registry_stats.return_value = "Registry stats"
    relay.tool_registry.get_server_tool_map_json.return_value = '{"servers": {}}'

    result = await relay._handle_list_downstream_servers_info()

    assert isinstance(result, types.CallToolResult)
    assert not result.isError
    assert len(result.content) == 1


# ===================== Resource and Performance Tests =====================


@pytest.mark.asyncio
async def test_memory_cleanup_after_initialization(valid_config):
    """Test memory cleanup after initialization."""
    initial_task_count = len(asyncio.all_tasks())

    relay = PanSecurityRelay("/test/config.json", security_scanner_env={})

    with patch("pan_mcp_relay.pan_security_relay.PanSecurityRelay._load_config") as mock_load_config:
        mock_load_config.return_value = valid_config["mcpServers"]

        with patch.object(relay, "_update_security_scanner", new_callable=AsyncMock):
            with patch.object(relay, "_update_tool_registry", new_callable=AsyncMock):
                await relay._initialize()

    await asyncio.sleep(0.1)

    final_task_count = len(asyncio.all_tasks())
    assert final_task_count - initial_task_count <= 2


@pytest.mark.asyncio
async def test_concurrent_tool_executions(relay):
    """Test handling multiple concurrent tool executions."""
    benign_scan_result = {
        "action": "allow",
        "category": "benign",
        "profile_id": "ba51dae8-4675-4f89-8027-9adcc01e41e3",
        "profile_name": "MCP-Security",
        "prompt_detected": {"dlp": False, "injection": False, "url_cats": False},
        "report_id": "Rfed6481f-b349-44c0-b6cb-72a4219efbc6",
        "response_detected": {"dlp": False, "url_cats": False},
        "scan_id": "fed6481f-b349-44c0-b6cb-72a4219efbc6",
        "tr_id": "12348ba3396e",
    }

    relay.tool_registry = Mock()
    relay.tool_registry.get_available_tools.return_value = [
        InternalTool(
            name="summarize_text_content",
            description="Summarize text content from documents",
            inputSchema={},
            annotations=None,
            server_name="benign_text_processor",
            state=ToolState.ENABLED,
        )
    ]
    relay.scanner = Mock()
    relay.scanner.scan_request = AsyncMock(return_value=benign_scan_result)
    relay.scanner.scan_response = AsyncMock(return_value=benign_scan_result)
    relay.scanner.should_block.return_value = False
    relay.scanner.pan_security_server = Mock()
    relay.scanner.pan_security_server.extract_text_content.return_value = "Text processing completed"

    with patch.object(relay, "_execute_on_server", new_callable=AsyncMock) as mock_execute:
        mock_execute.return_value = types.CallToolResult(
            content=[types.TextContent(type="text", text="Text processing completed")], isError=False
        )

        tasks = [relay._call_tool("summarize_text_content", {"text": f"Document content {i}"}) for i in range(3)]

        results = await asyncio.gather(*tasks)

        for result in results:
            assert isinstance(result, types.CallToolResult)
            assert not result.isError

        assert mock_execute.call_count == 3
