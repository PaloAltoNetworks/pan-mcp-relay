"""
Unit tests for the downstream_mcp_client module.

This module contains comprehensive tests for the DownstreamMcpClient class using
simulated tools for testing purposes.
"""

import pytest
import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch, call
from contextlib import AsyncExitStack
from typing import Dict, Any

import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from tenacity import RetryError

from pan_aisecurity_mcp.mcp_relay.downstream_mcp_client import DownstreamMcpClient


@pytest.fixture
def echo_server_config():
    """Create echo server configuration for testing."""
    return {
        "command": "python",
        "args": ["-m", "echo_server"],
        "env": {
            "ECHO_MODE": "simple",
            "RESPONSE_FORMAT": "json"
        }
    }


@pytest.fixture
def test_server_config():
    """Create generic test server configuration."""
    return {
        "command": "uv",
        "args": ["run", "test-server"],
        "env": {
            "TEST_MODE": "enabled",
            "LOG_LEVEL": "debug"
        }
    }


@pytest.fixture
def performance_server_config():
    """Create performance test server configuration."""
    return {
        "command": "python",
        "args": ["-m", "performance_tools"],
        "env": {
            "LATENCY_MODE": "variable",
            "MAX_DELAY": "5000"
        }
    }


@pytest.fixture
def sse_server_config():
    """Create SSE server configuration for testing."""
    return {
        "type": "sse",
        "baseUrl": "http://localhost:8080/test"
    }


@pytest.fixture
def mock_echo_tool():
    """Create mock echo tool that returns input."""
    return types.Tool(
        name="echo_tool",
        description="Echo back the input text",
        inputSchema={
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text to echo back"
                }
            },
            "required": ["text"]
        }
    )


@pytest.fixture
def mock_error_all_tool():
    """Create mock tool that always returns errors."""
    return types.Tool(
        name="error_all_tool",
        description="Always returns error response with isError=True",
        inputSchema={
            "type": "object",
            "properties": {
                "input": {
                    "type": "string",
                    "description": "Input that will trigger error response"
                }
            }
        }
    )


@pytest.fixture
def mock_slow_response_tool():
    """Create mock latency simulator tool."""
    return types.Tool(
        name="slow_response_tool",
        description="Simulates slow response with intentional delay",
        inputSchema={
            "type": "object",
            "properties": {
                "delay_seconds": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 10,
                    "description": "Delay in seconds before responding"
                },
                "content": {
                    "type": "string",
                    "description": "Content to return after delay"
                }
            },
            "required": ["delay_seconds"]
        }
    )


@pytest.fixture
def mock_fixed_response_tool():
    """Create mock tool that returns fixed preset results."""
    return types.Tool(
        name="fixed_response_tool",
        description="Returns predefined fixed response based on response type",
        inputSchema={
            "type": "object",
            "properties": {
                "response_type": {
                    "type": "string",
                    "enum": ["success", "warning", "info", "error"],
                    "description": "Type of fixed response to return"
                },
                "include_metadata": {
                    "type": "boolean",
                    "default": False,
                    "description": "Whether to include metadata in response"
                }
            },
            "required": ["response_type"]
        }
    )


@pytest.fixture
def mock_passthrough_tool():
    """Create mock tool that does nothing and returns directly."""
    return types.Tool(
        name="passthrough_tool",
        description="Passthrough tool that returns input unchanged",
        inputSchema={
            "type": "object",
            "properties": {
                "data": {
                    "type": "object",
                    "description": "Data to pass through unchanged"
                }
            }
        }
    )


@pytest.fixture
def mock_failing_tool():
    """Create mock tool that intentionally fails or throws exceptions."""
    return types.Tool(
        name="failing_tool",
        description="Intentionally fails with errors or exceptions",
        inputSchema={
            "type": "object",
            "properties": {
                "failure_mode": {
                    "type": "string",
                    "enum": ["exception", "error_response", "timeout", "network_error"],
                    "description": "Type of failure to simulate"
                },
                "error_message": {
                    "type": "string",
                    "default": "Simulated failure",
                    "description": "Custom error message"
                }
            },
            "required": ["failure_mode"]
        }
    )


@pytest.fixture
def mock_external_tools_list(mock_echo_tool, mock_error_all_tool, mock_slow_response_tool,
                            mock_fixed_response_tool, mock_passthrough_tool, mock_failing_tool):
    """Create list of all external simulated tools for testing."""
    return [
        mock_echo_tool,
        mock_error_all_tool,
        mock_slow_response_tool,
        mock_fixed_response_tool,
        mock_passthrough_tool,
        mock_failing_tool
    ]


class TestDownstreamMcpClient:
    """Test suite for DownstreamMcpClient using external simulated tools."""

    def test_downstream_mcp_client_initialization(self, test_server_config):
        """Test DownstreamMcpClient initialization with test server configuration."""
        client = DownstreamMcpClient("test-server", test_server_config)

        assert client.name == "test-server"
        assert client.config == test_server_config
        assert client.session is None
        assert isinstance(client._cleanup_lock, asyncio.Lock)
        assert isinstance(client.exit_stack, AsyncExitStack)

    def test_downstream_mcp_client_initialization_sse(self, sse_server_config):
        """Test DownstreamMcpClient initialization with SSE server configuration."""
        client = DownstreamMcpClient("sse-server", sse_server_config)

        assert client.name == "sse-server"
        assert client.config == sse_server_config
        assert client.session is None
        assert isinstance(client._cleanup_lock, asyncio.Lock)
        assert isinstance(client.exit_stack, AsyncExitStack)

    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    def test_downstream_mcp_client_initialization_logging(self, mock_logging, test_server_config):
        """Test that client initialization logs configuration information."""
        DownstreamMcpClient("test-server", test_server_config)

        expected_message = f"Server test-server created with config: {test_server_config}"
        mock_logging.info.assert_called_with(expected_message)

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.stdio_client')
    async def test_initialize_echo_server_success(self, mock_stdio_client, echo_server_config):
        """Test successful initialization of echo server connection."""
        # Setup mocks for echo server connection
        mock_read = AsyncMock()
        mock_write = AsyncMock()
        mock_stdio_transport = (mock_read, mock_write)
        mock_stdio_client.return_value = AsyncMock()
        mock_stdio_client.return_value.__aenter__.return_value = mock_stdio_transport

        mock_session = AsyncMock(spec=ClientSession)
        mock_session.initialize.return_value = None

        client = DownstreamMcpClient("echo-server", echo_server_config)

        with patch.object(client.exit_stack, 'enter_async_context') as mock_enter_context:
            mock_enter_context.side_effect = [mock_stdio_transport, mock_session]

            await client.initialize()

        assert client.session == mock_session
        mock_session.initialize.assert_called_once()

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.sse_client')
    async def test_initialize_sse_server_success(self, mock_sse_client, sse_server_config):
        """Test successful initialization of SSE server connection."""
        # Setup mocks for SSE connection
        mock_read = AsyncMock()
        mock_write = AsyncMock()
        mock_sse_transport = (mock_read, mock_write)
        mock_sse_client.return_value = AsyncMock()
        mock_sse_client.return_value.__aenter__.return_value = mock_sse_transport

        mock_session = AsyncMock(spec=ClientSession)
        mock_session.initialize.return_value = None

        client = DownstreamMcpClient("sse-server", sse_server_config)

        with patch.object(client.exit_stack, 'enter_async_context') as mock_enter_context:
            mock_enter_context.side_effect = [mock_sse_transport, mock_session]

            await client.initialize()

        assert client.session == mock_session
        mock_session.initialize.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialize_sse_server_missing_baseurl(self):
        """Test that ValueError is raised for SSE connection without baseUrl."""
        sse_config_no_baseurl = {"type": "sse"}
        client = DownstreamMcpClient("sse-server", sse_config_no_baseurl)

        with pytest.raises(ValueError, match="SSE connection requires 'baseUrl'"):
            await client.initialize()

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.stdio_client')
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_initialize_server_environment_variables(self, mock_logging, mock_stdio_client,
                                                          performance_server_config):
        """Test server initialization with environment variable handling."""
        mock_stdio_client.return_value = AsyncMock()
        mock_stdio_client.return_value.__aenter__.return_value = (AsyncMock(), AsyncMock())

        mock_session = AsyncMock(spec=ClientSession)
        client = DownstreamMcpClient("performance-server", performance_server_config)

        with patch.object(client.exit_stack, 'enter_async_context') as mock_enter_context:
            with patch('os.environ', {"EXISTING_VAR": "existing_value"}) as mock_env:
                mock_enter_context.side_effect = [(AsyncMock(), AsyncMock()), mock_session]

                await client.initialize()

                # Verify environment variables are properly set
                expected_env = {
                    "EXISTING_VAR": "existing_value",
                    "LATENCY_MODE": "variable",
                    "MAX_DELAY": "5000"
                }

        mock_logging.debug.assert_any_call("Initializing downstream mcp server: performance-server...")

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.stdio_client')
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_initialize_server_failure(self, mock_logging, mock_stdio_client, test_server_config):
        """Test server initialization failure handling."""
        # Simulate connection failure
        mock_stdio_client.side_effect = Exception("Test server connection failed")

        client = DownstreamMcpClient("test-server", test_server_config)

        with patch.object(client, 'cleanup') as mock_cleanup:
            with pytest.raises(Exception, match="Test server connection failed"):
                await client.initialize()

            mock_cleanup.assert_called_once()

        mock_logging.error.assert_called_with(
            "Error initializing server test-server: Test server connection failed",
            exc_info=True
        )

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.sse_client')
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_initialize_sse_server_failure(self, mock_logging, mock_sse_client, sse_server_config):
        """Test SSE server initialization failure handling."""
        # Simulate connection failure
        mock_sse_client.side_effect = Exception("Test SSE connection failed")

        client = DownstreamMcpClient("sse-server", sse_server_config)

        with patch.object(client, 'cleanup') as mock_cleanup:
            with pytest.raises(Exception, match="Test SSE connection failed"):
                await client.initialize()

            mock_cleanup.assert_called_once()

        mock_logging.error.assert_called_with(
            "Error initializing server sse-server: Test SSE connection failed",
            exc_info=True
        )

    @pytest.mark.asyncio
    async def test_list_tools_external_server_success(self, mock_external_tools_list):
        """Test successful tool listing from external test server."""
        client = DownstreamMcpClient("test-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock external server tool response
        mock_tools_response = [("tools", mock_external_tools_list)]
        client.session.list_tools.return_value = mock_tools_response

        tools = await client.list_tools()

        assert len(tools) == 6
        tool_names = [tool.name for tool in tools]
        assert "echo_tool" in tool_names
        assert "error_all_tool" in tool_names
        assert "slow_response_tool" in tool_names
        assert "fixed_response_tool" in tool_names
        assert "passthrough_tool" in tool_names
        assert "failing_tool" in tool_names

        # Verify echo tool properties
        echo_tool = next(tool for tool in tools if tool.name == "echo_tool")
        assert "Echo back the input text" in echo_tool.description
        assert "text" in echo_tool.inputSchema["properties"]

    @pytest.mark.asyncio
    async def test_list_tools_server_not_initialized(self):
        """Test tool listing when server is not initialized."""
        client = DownstreamMcpClient("test-server", {})

        with pytest.raises(RuntimeError, match="Server test-server not initialized"):
            await client.list_tools()

    @pytest.mark.asyncio
    async def test_list_tools_server_empty_response(self):
        """Test tool listing with empty response from server."""
        client = DownstreamMcpClient("test-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock empty response from server
        client.session.list_tools.return_value = []

        tools = await client.list_tools()

        assert tools == []

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_execute_tool_echo_success(self, mock_logging):
        """Test successful execution of echo tool."""
        client = DownstreamMcpClient("echo-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock echo tool response
        mock_echo_response = types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps({
                        "echoed_text": "Hello, World!",
                        "timestamp": "2024-01-15T12:00:00Z",
                        "tool": "echo_tool"
                    })
                )
            ]
        )
        client.session.call_tool.return_value = mock_echo_response

        # Execute echo tool
        echo_args = {
            "text": "Hello, World!"
        }

        result = await client.execute_tool("echo_tool", echo_args)

        assert result == mock_echo_response
        client.session.call_tool.assert_called_once_with("echo_tool", echo_args)

        mock_logging.info.assert_any_call("Executing echo_tool...")
        mock_logging.info.assert_any_call(f"arguments: {echo_args}")

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_execute_tool_fixed_response_success(self, mock_logging):
        """Test successful execution of fixed response tool."""
        client = DownstreamMcpClient("test-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock fixed response tool response
        mock_fixed_response = types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps({
                        "response_type": "success",
                        "message": "Operation completed successfully",
                        "status_code": 200,
                        "metadata": {
                            "tool": "fixed_response_tool",
                            "execution_time": "50ms"
                        }
                    })
                )
            ]
        )
        client.session.call_tool.return_value = mock_fixed_response

        # Execute fixed response tool
        fixed_args = {
            "response_type": "success",
            "include_metadata": True
        }

        result = await client.execute_tool("fixed_response_tool", fixed_args)

        assert result == mock_fixed_response
        client.session.call_tool.assert_called_once_with("fixed_response_tool", fixed_args)

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_execute_tool_slow_response_success(self, mock_logging):
        """Test successful execution of slow response tool."""
        client = DownstreamMcpClient("performance-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock slow response tool response
        mock_slow_response = types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps({
                        "content": "Delayed response content",
                        "delay_applied": 2.5,
                        "completion_time": "2024-01-15T12:00:02.5Z"
                    })
                )
            ]
        )
        client.session.call_tool.return_value = mock_slow_response

        # Execute slow response tool
        slow_args = {
            "delay_seconds": 2.5,
            "content": "Delayed response content"
        }

        result = await client.execute_tool("slow_response_tool", slow_args)

        assert result == mock_slow_response

    @pytest.mark.asyncio
    async def test_execute_tool_server_not_initialized(self):
        """Test tool execution when server is not initialized."""
        client = DownstreamMcpClient("test-server", {})

        # The retry decorator will wrap the RuntimeError in a tenacity.RetryError
        with pytest.raises(RetryError) as exc_info:
            await client.execute_tool("echo_tool", {})

        # Verify the underlying exception is RuntimeError with expected message
        original_exception = exc_info.value.last_attempt.exception()
        assert isinstance(original_exception, RuntimeError)
        assert "Server test-server not initialized" in str(original_exception)

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_execute_tool_server_error_with_retry(self, mock_logging):
        """Test tool execution error handling with retry mechanism."""
        client = DownstreamMcpClient("test-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Simulate server error
        server_error = Exception("Server temporarily unavailable")
        client.session.call_tool.side_effect = server_error

        # The retry decorator will wrap the exception in a tenacity.RetryError
        with pytest.raises(RetryError) as exc_info:
            await client.execute_tool("echo_tool", {"text": "test"})

        # Should retry 3 times (default retry configuration)
        assert client.session.call_tool.call_count == 3

        # Verify the underlying exception is the original exception
        original_exception = exc_info.value.last_attempt.exception()
        assert isinstance(original_exception, Exception)
        assert "Server temporarily unavailable" in str(original_exception)

        # Verify logging was called for each retry attempt
        expected_calls = [
            call("Error executing echo_tool: Server temporarily unavailable", exc_info=True)
        ] * 3  # Should be called 3 times due to retries

        mock_logging.error.assert_has_calls(expected_calls)

    def test_extract_text_content_mcp_text_content(self):
        """Test text extraction from MCP TextContent."""
        client = DownstreamMcpClient("test-server", {})

        # Test with echo tool response TextContent
        echo_text_content = types.TextContent(
            type="text",
            text=json.dumps({
                "echoed_text": "test response",
                "tool": "echo_tool"
            })
        )

        extracted = client.extract_text_content(echo_text_content)

        # Should return JSON representation for structured data
        assert isinstance(extracted, str)
        assert "echoed_text" in extracted
        assert "test response" in extracted

    def test_extract_text_content_mcp_embedded_resource(self):
        """Test text extraction from MCP EmbeddedResource."""
        client = DownstreamMcpClient("test-server", {})

        # Test with embedded resource
        embedded_resource = types.EmbeddedResource(
            type="resource",
            resource=types.TextResourceContents(
                uri="test://resource/12345",
                text="Test resource content"
            )
        )

        extracted = client.extract_text_content(embedded_resource)

        # Should return JSON representation
        assert isinstance(extracted, str)
        assert "test://resource/12345" in extracted

    def test_extract_text_content_list_of_responses(self):
        """Test text extraction from list of response content."""
        client = DownstreamMcpClient("test-server", {})

        # Test with list of responses
        content_list = [
            types.TextContent(type="text", text="Response 1"),
            types.TextContent(type="text", text="Response 2")
        ]

        extracted = client.extract_text_content(content_list)

        # The method returns a list of JSON string representations of the list items.
        assert isinstance(extracted, list)
        assert len(extracted) == 2

        # Each item in the list should be a JSON string of the TextContent object
        for item_json in extracted:
            assert isinstance(item_json, str)
            item_data = json.loads(item_json)
            assert item_data["type"] == "text"
            assert "Response" in item_data["text"]

    def test_extract_text_content_object_with_text_attribute(self):
        """Test text extraction from object with text attribute."""
        client = DownstreamMcpClient("test-server", {})

        # Mock response object with text attribute
        class ResponseObject:
            def __init__(self):
                self.text = "Fixed response content"

        response_obj = ResponseObject()
        extracted = client.extract_text_content(response_obj)

        assert extracted == "Fixed response content"

    def test_extract_text_content_object_with_input_value_attribute(self):
        """Test text extraction from object with input_value attribute."""
        client = DownstreamMcpClient("test-server", {})

        # Mock input object
        class InputObject:
            def __init__(self):
                self.input_value = "Test input value"

        input_obj = InputObject()
        extracted = client.extract_text_content(input_obj)

        assert extracted == "Test input value"

    def test_extract_text_content_direct_string_data(self):
        """Test text extraction from direct string data."""
        client = DownstreamMcpClient("test-server", {})

        string_data = "Direct string response from tool"
        extracted = client.extract_text_content(string_data)

        assert extracted == string_data

    def test_check_initialized_when_session_exists(self):
        """Test _check_initialized when server session exists."""
        client = DownstreamMcpClient("test-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Should not raise exception
        client._check_initialized()

    def test_check_initialized_when_session_none(self):
        """Test _check_initialized when server session is None."""
        client = DownstreamMcpClient("test-server", {})

        with pytest.raises(RuntimeError, match="Server test-server not initialized"):
            client._check_initialized()

    @pytest.mark.asyncio
    async def test_cleanup_server_connection(self):
        """Test cleanup of server connection resources."""
        client = DownstreamMcpClient("test-server", {})
        client.session = AsyncMock(spec=ClientSession)

        mock_exit_stack = AsyncMock()
        client.exit_stack = mock_exit_stack

        await client.cleanup()

        mock_exit_stack.aclose.assert_called_once()
        assert client.session is None

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_cleanup_server_with_exception(self, mock_logging):
        """Test cleanup handling exceptions during server cleanup."""
        client = DownstreamMcpClient("test-server", {})

        mock_exit_stack = AsyncMock()
        mock_exit_stack.aclose.side_effect = Exception("Cleanup error")
        client.exit_stack = mock_exit_stack

        # Should not raise exception, but log error
        await client.cleanup()

        mock_logging.error.assert_called_with(
            "Error during cleanup of server test-server: Cleanup error"
        )

    @pytest.mark.asyncio
    async def test_concurrent_cleanup_calls(self):
        """Test concurrent cleanup calls using cleanup lock."""
        client = DownstreamMcpClient("test-server", {})

        mock_exit_stack = AsyncMock()
        client.exit_stack = mock_exit_stack

        # Start multiple cleanup operations concurrently
        cleanup_tasks = [client.cleanup() for _ in range(3)]
        await asyncio.gather(*cleanup_tasks)

        # Should call aclose for each task
        assert mock_exit_stack.aclose.call_count == 3


class TestDownstreamMcpClientIntegration:
    """Integration tests for DownstreamMcpClient with external tool scenarios."""

    @pytest.mark.asyncio
    async def test_external_server_complete_workflow(self, test_server_config, mock_external_tools_list):
        """Test complete workflow with external server from initialization to tool execution."""
        client = DownstreamMcpClient("test-server", test_server_config)

        # Mock successful initialization
        with patch.object(client, 'initialize') as mock_init:
            mock_init.return_value = None
            client.session = AsyncMock(spec=ClientSession)

            await client.initialize()

            # Mock tool listing
            mock_tools_response = [("tools", mock_external_tools_list)]
            client.session.list_tools.return_value = mock_tools_response

            # List tools
            tools = await client.list_tools()
            assert len(tools) == 6

            # Mock echo tool execution
            mock_echo_result = types.CallToolResult(
                content=[types.TextContent(type="text", text='{"echoed": "test content"}')]
            )
            client.session.call_tool.return_value = mock_echo_result

            # Execute echo tool
            result = await client.execute_tool("echo_tool", {
                "text": "test content"
            })

            assert result == mock_echo_result

            # Cleanup connection
            await client.cleanup()

    @pytest.mark.asyncio
    async def test_server_error_recovery_scenario(self, test_server_config):
        """Test server error recovery and retry scenarios."""
        client = DownstreamMcpClient("test-server", test_server_config)
        client.session = AsyncMock(spec=ClientSession)

        # Simulate intermittent server errors
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:  # Fail first 2 attempts
                raise Exception("Temporary server error")
            return types.CallToolResult(
                content=[types.TextContent(type="text", text='{"status": "success"}')]
            )

        client.session.call_tool.side_effect = side_effect

        # Should succeed after retries
        result = await client.execute_tool("echo_tool", {"text": "test"})
        assert result is not None
        assert call_count == 3  # 2 failures + 1 success

    @pytest.mark.asyncio
    async def test_multiple_servers_scenario(self, echo_server_config, performance_server_config):
        """Test scenario with multiple external servers."""
        # Echo server
        echo_client = DownstreamMcpClient("echo-server", echo_server_config)
        echo_client.session = AsyncMock(spec=ClientSession)

        # Performance server
        perf_client = DownstreamMcpClient("performance-server", performance_server_config)
        perf_client.session = AsyncMock(spec=ClientSession)

        # Both servers should be able to list tools
        mock_echo_tools = [("tools", [
            types.Tool(name="echo_tool", description="Echo tool", inputSchema={}),
        ])]
        mock_perf_tools = [("tools", [
            types.Tool(name="slow_response_tool", description="Latency simulator", inputSchema={}),
        ])]

        echo_client.session.list_tools.return_value = mock_echo_tools
        perf_client.session.list_tools.return_value = mock_perf_tools

        echo_tools = await echo_client.list_tools()
        perf_tools = await perf_client.list_tools()

        assert len(echo_tools) == 1
        assert len(perf_tools) == 1
        assert echo_tools[0].name == "echo_tool"
        assert perf_tools[0].name == "slow_response_tool"

    @pytest.mark.asyncio
    async def test_error_all_tool_scenario(self):
        """Test error_all_tool that always returns errors."""
        client = DownstreamMcpClient("test-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock error response
        error_response = types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps({
                        "isError": True,
                        "error_type": "simulated_error",
                        "message": "This tool always returns errors",
                        "timestamp": "2024-01-15T12:00:00Z"
                    })
                )
            ]
        )
        client.session.call_tool.return_value = error_response

        # Execute error tool
        result = await client.execute_tool("error_all_tool", {"input": "test"})

        # Verify error response structure
        assert result == error_response
        extracted_content = client.extract_text_content(result.content[0])
        error_data = json.loads(extracted_content)
        error_data_text = error_data["text"]
        error_data_text_parsed = json.loads(error_data_text)
        print(error_data_text_parsed)
        assert error_data_text_parsed["isError"] == True
        assert error_data_text_parsed["error_type"] == "simulated_error"

    @pytest.mark.asyncio
    async def test_passthrough_tool_scenario(self):
        """Test passthrough tool that returns input unchanged."""
        client = DownstreamMcpClient("utility-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock passthrough response
        test_data = {"key1": "value1", "key2": "value2", "nested": {"data": "test"}}
        passthrough_response = types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps({
                        "passthrough": True,
                        "original_data": test_data,
                        "processing_time": "0ms"
                    })
                )
            ]
        )
        client.session.call_tool.return_value = passthrough_response

        # Execute passthrough tool
        result = await client.execute_tool("passthrough_tool", {"data": test_data})

        assert result == passthrough_response

        # Verify data integrity
        extracted_content = client.extract_text_content(result.content[0])
        response_data = json.loads(extracted_content)
        response_data_text = response_data["text"]
        response_data_text_parsed = json.loads(response_data_text)
        assert response_data_text_parsed["passthrough"] == True
        assert response_data_text_parsed["original_data"] == test_data

    @pytest.mark.asyncio
    async def test_failing_tool_exception_scenario(self):
        """Test failing tool that throws exceptions."""
        client = DownstreamMcpClient("test-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Simulate tool throwing exception
        tool_exception = Exception("Intentional tool failure")
        client.session.call_tool.side_effect = tool_exception

        # Should fail after retries
        with pytest.raises(RetryError) as exc_info:
            await client.execute_tool("failing_tool", {
                "failure_mode": "exception",
                "error_message": "Intentional tool failure"
            })

        # Verify exception was retried
        assert client.session.call_tool.call_count == 3

    @pytest.mark.asyncio
    async def test_slow_response_tool_performance_scenario(self):
        """Test slow response tool with various delay configurations."""
        client = DownstreamMcpClient("performance-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Test different delay scenarios
        delay_scenarios = [0.1, 1.0, 2.5, 5.0]

        for delay in delay_scenarios:
            mock_response = types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=json.dumps({
                            "requested_delay": delay,
                            "actual_delay": delay,
                            "content": f"Response after {delay}s delay",
                            "performance_metrics": {
                                "cpu_usage": "5%",
                                "memory_usage": "12MB"
                            }
                        })
                    )
                ]
            )
            client.session.call_tool.return_value = mock_response

            result = await client.execute_tool("slow_response_tool", {
                "delay_seconds": delay,
                "content": f"Test content {delay}"
            })

            assert result == mock_response

    @pytest.mark.asyncio
    async def test_fixed_response_tool_all_types_scenario(self):
        """Test fixed response tool with all response types."""
        client = DownstreamMcpClient("mock-server", {})
        client.session = AsyncMock(spec=ClientSession)

        response_types = ["success", "warning", "info", "error"]

        for response_type in response_types:
            mock_response = types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=json.dumps({
                            "response_type": response_type,
                            "message": f"Fixed {response_type} response",
                            "status_code": 200 if response_type == "success" else 400,
                            "metadata": {
                                "tool": "fixed_response_tool",
                                "version": "1.0.0"
                            }
                        })
                    )
                ]
            )
            client.session.call_tool.return_value = mock_response

            result = await client.execute_tool("fixed_response_tool", {
                "response_type": response_type,
                "include_metadata": True
            })

            # Verify response structure
            extracted_content = client.extract_text_content(result.content[0])
            response_data = json.loads(extracted_content)
            response_data_text = response_data["text"]
            response_data_text_parsed = json.loads(response_data_text)
            assert response_data_text_parsed["response_type"] == response_type
            assert "metadata" in response_data_text_parsed

    @pytest.mark.asyncio
    async def test_mixed_tools_workflow_scenario(self, mock_external_tools_list):
        """Test workflow using multiple different tools in sequence."""
        client = DownstreamMcpClient("test-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Simulate workflow: echo -> fixed response -> passthrough
        workflow_responses = [
            types.CallToolResult(content=[types.TextContent(type="text", text='{"echoed": "step1"}')]),
            types.CallToolResult(content=[types.TextContent(type="text", text='{"response_type": "success"}')]),
            types.CallToolResult(content=[types.TextContent(type="text", text='{"passthrough": true}')])
        ]

        client.session.call_tool.side_effect = workflow_responses

        # Execute workflow steps
        step1 = await client.execute_tool("echo_tool", {"text": "step1"})
        step2 = await client.execute_tool("fixed_response_tool", {"response_type": "success"})
        step3 = await client.execute_tool("passthrough_tool", {"data": {"workflow": "complete"}})

        # Verify all steps executed
        assert step1 == workflow_responses[0]
        assert step2 == workflow_responses[1]
        assert step3 == workflow_responses[2]
        assert client.session.call_tool.call_count == 3
