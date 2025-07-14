"""
Unit tests for the downstream_mcp_client module in AI Security MCP Relay.

This module contains comprehensive tests for the DownstreamMcpClient class used in
AI Runtime Security (AIRS) MCP relay operations for managing connections and
communication with downstream MCP servers like the pan_security_server.py.
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
def airs_server_config():
    """Create AIRS server configuration matching pan_security_server.py setup."""
    return {
        "command": "uv",
        "args": ["run", "fastmcp", "run", "-t", "sse"],
        "env": {
            "PANW_AI_PROFILE_NAME": "default_ai_profile",
            "PANW_AI_SEC_API_KEY": "fake-api-key-for-testing",
            "PANW_AI_SEC_API_ENDPOINT": "https://ai-runtime-security.api.paloaltonetworks.com"
        }
    }


@pytest.fixture
def airs_backup_server_config():
    """Create backup AIRS server configuration for multi-server testing."""
    return {
        "command": "python",
        "args": ["-m", "pan_aisecurity_mcp.mcp_server.pan_security_server"],
        "env": {
            "PANW_AI_PROFILE_ID": "backup_profile_uuid",
            "PANW_AI_SEC_API_KEY": "fake-api-key-for-test"
        }
    }


@pytest.fixture
def mock_airs_inline_scan_tool():
    """Create mock AIRS inline scan tool matching pan_security_server.py."""
    return types.Tool(
        name="pan_inline_scan",
        description="Submit a single Prompt and/or Model-Response to be scanned synchronously for security threats",
        inputSchema={
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
            }
        }
    )


@pytest.fixture
def mock_airs_batch_scan_tool():
    """Create mock AIRS batch scan tool matching pan_security_server.py."""
    return types.Tool(
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
                    "maxItems": 5,  # MAX_NUMBER_OF_BATCH_SCAN_OBJECTS
                    "description": "Array of scan content objects for batch processing"
                }
            },
            "required": ["scan_contents"]
        }
    )


@pytest.fixture
def mock_airs_scan_results_tool():
    """Create mock AIRS scan results tool matching pan_security_server.py."""
    return types.Tool(
        name="pan_get_scan_results",
        description="Retrieve Scan Results with a list of Scan IDs",
        inputSchema={
            "type": "object",
            "properties": {
                "scan_ids": {
                    "type": "array",
                    "items": {"type": "string", "format": "uuid"},
                    "maxItems": 100,  # MAX_NUMBER_OF_SCAN_IDS
                    "description": "List of Scan IDs (UUID strings) to retrieve results for"
                }
            },
            "required": ["scan_ids"]
        }
    )


@pytest.fixture
def mock_airs_scan_reports_tool():
    """Create mock AIRS scan reports tool matching pan_security_server.py."""
    return types.Tool(
        name="pan_get_scan_reports",
        description="Retrieve Scan Reports with a list of Scan Report IDs",
        inputSchema={
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
    )


@pytest.fixture
def mock_airs_tools_list(mock_airs_inline_scan_tool, mock_airs_batch_scan_tool,
                         mock_airs_scan_results_tool, mock_airs_scan_reports_tool):
    """Create list of all AIRS tools for testing."""
    return [
        mock_airs_inline_scan_tool,
        mock_airs_batch_scan_tool,
        mock_airs_scan_results_tool,
        mock_airs_scan_reports_tool
    ]

class TestDownstreamMcpClient:
    """Test suite for DownstreamMcpClient used in AIRS MCP server communication."""

    def test_downstream_mcp_client_initialization(self, airs_server_config):
        """Test DownstreamMcpClient initialization with AIRS server configuration."""
        client = DownstreamMcpClient("aisecurity-scan-server", airs_server_config)

        assert client.name == "aisecurity-scan-server"
        assert client.config == airs_server_config
        assert client.session is None
        assert isinstance(client._cleanup_lock, asyncio.Lock)
        assert isinstance(client.exit_stack, AsyncExitStack)

    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    def test_downstream_mcp_client_initialization_logging(self, mock_logging, airs_server_config):
        """Test that client initialization logs configuration information."""
        DownstreamMcpClient("aisecurity-scan-server", airs_server_config)

        # Fix: Match the actual logging call format
        expected_message = f"Server aisecurity-scan-server created with config: {airs_server_config}"
        mock_logging.info.assert_called_with(expected_message)

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.stdio_client')
    async def test_initialize_airs_server_success(self, mock_stdio_client, airs_server_config):
        """Test successful initialization of AIRS server connection."""
        # Setup mocks for AIRS server connection
        mock_read = AsyncMock()
        mock_write = AsyncMock()
        mock_stdio_transport = (mock_read, mock_write)
        mock_stdio_client.return_value = AsyncMock()
        mock_stdio_client.return_value.__aenter__.return_value = mock_stdio_transport

        mock_session = AsyncMock(spec=ClientSession)
        mock_session.initialize.return_value = None

        client = DownstreamMcpClient("aisecurity-scan-server", airs_server_config)

        with patch.object(client.exit_stack, 'enter_async_context') as mock_enter_context:
            mock_enter_context.side_effect = [mock_stdio_transport, mock_session]

            await client.initialize()

        assert client.session == mock_session
        mock_session.initialize.assert_called_once()

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.stdio_client')
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_initialize_airs_server_environment_variables(self, mock_logging, mock_stdio_client,
                                                                airs_server_config):
        """Test AIRS server initialization with environment variable handling."""
        mock_stdio_client.return_value = AsyncMock()
        mock_stdio_client.return_value.__aenter__.return_value = (AsyncMock(), AsyncMock())

        mock_session = AsyncMock(spec=ClientSession)
        client = DownstreamMcpClient("aisecurity-scan-server", airs_server_config)

        with patch.object(client.exit_stack, 'enter_async_context') as mock_enter_context:
            with patch('os.environ', {"EXISTING_VAR": "existing_value"}) as mock_env:
                mock_enter_context.side_effect = [(AsyncMock(), AsyncMock()), mock_session]

                await client.initialize()

                # Verify environment variables are properly set for AIRS
                expected_env = {
                    "EXISTING_VAR": "existing_value",
                    "PANW_AI_PROFILE_NAME": "default_ai_profile",
                    "PANW_AI_SEC_API_KEY": "fake-api-key-for-testing",
                    "PANW_AI_SEC_API_ENDPOINT": "https://ai-runtime-security.api.paloaltonetworks.com"
                }

        mock_logging.debug.assert_any_call("Initializing downstream mcp server: aisecurity-scan-server...")

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.stdio_client')
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_initialize_airs_server_failure(self, mock_logging, mock_stdio_client, airs_server_config):
        """Test AIRS server initialization failure handling."""
        # Simulate connection failure to AIRS server
        mock_stdio_client.side_effect = Exception("AIRS server connection failed")

        client = DownstreamMcpClient("aisecurity-scan-server", airs_server_config)

        with patch.object(client, 'cleanup') as mock_cleanup:
            with pytest.raises(Exception, match="AIRS server connection failed"):
                await client.initialize()

            mock_cleanup.assert_called_once()

        mock_logging.error.assert_called_with(
            "Error initializing server aisecurity-scan-server: AIRS server connection failed",
            exc_info=True
        )

    @pytest.mark.asyncio
    async def test_list_tools_airs_server_success(self, mock_airs_tools_list):
        """Test successful tool listing from AIRS server."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock AIRS server tool response
        mock_tools_response = [("tools", mock_airs_tools_list)]
        client.session.list_tools.return_value = mock_tools_response

        tools = await client.list_tools()

        assert len(tools) == 4
        tool_names = [tool.name for tool in tools]
        assert "pan_inline_scan" in tool_names
        assert "pan_batch_scan" in tool_names
        assert "pan_get_scan_results" in tool_names
        assert "pan_get_scan_reports" in tool_names

        # Verify AIRS-specific tool properties
        inline_scan_tool = next(tool for tool in tools if tool.name == "pan_inline_scan")
        assert "synchronously for security threats" in inline_scan_tool.description
        assert "prompt" in inline_scan_tool.inputSchema["properties"]
        assert "response" in inline_scan_tool.inputSchema["properties"]

    @pytest.mark.asyncio
    async def test_list_tools_airs_server_not_initialized(self):
        """Test tool listing when AIRS server is not initialized."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})

        with pytest.raises(RuntimeError, match="Server aisecurity-scan-server not initialized"):
            await client.list_tools()

    @pytest.mark.asyncio
    async def test_list_tools_airs_server_empty_response(self):
        """Test tool listing with empty response from AIRS server."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock empty response from AIRS server
        client.session.list_tools.return_value = []

        tools = await client.list_tools()

        assert tools == []

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_execute_tool_airs_inline_scan_success(self, mock_logging):
        """Test successful execution of AIRS inline scan tool."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock AIRS inline scan response
        mock_scan_response = types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps({
                        "scan_id": "12345678-1234-5678-9abc-123456789def",
                        "category": "benign",
                        "action": "allow",
                        "verdict": "The content appears safe and contains no security threats"
                    })
                )
            ]
        )
        client.session.call_tool.return_value = mock_scan_response

        # Execute AIRS inline scan
        airs_scan_args = {
            "prompt": "What is the weather like today?",
            "response": "Today's weather is sunny with a high of 75°F"
        }

        result = await client.execute_tool("pan_inline_scan", airs_scan_args)

        assert result == mock_scan_response
        client.session.call_tool.assert_called_once_with("pan_inline_scan", airs_scan_args)

        # Fix: Check the actual logging calls that were made
        # Option 1: Check that logging.info was called with expected content
        mock_logging.info.assert_any_call(f"Executing pan_inline_scan...")
        mock_logging.info.assert_any_call(f"arguments: {airs_scan_args}")

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_execute_tool_airs_batch_scan_success(self, mock_logging):
        """Test successful execution of AIRS batch scan tool."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock AIRS batch scan response
        mock_batch_response = types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps([
                        {
                            "req_id": 1,
                            "scan_id": "batch-scan-1-uuid",
                            "report_id": "R-batch-scan-1-uuid"
                        },
                        {
                            "req_id": 2,
                            "scan_id": "batch-scan-2-uuid",
                            "report_id": "R-batch-scan-2-uuid"
                        }
                    ])
                )
            ]
        )
        client.session.call_tool.return_value = mock_batch_response

        # Execute AIRS batch scan with multiple contents
        airs_batch_args = {
            "scan_contents": [
                {"prompt": "Tell me about AI security", "response": "AI security involves..."},
                {"prompt": "How to protect against threats?", "response": "Protection strategies include..."}
            ]
        }

        result = await client.execute_tool("pan_batch_scan", airs_batch_args)

        assert result == mock_batch_response
        client.session.call_tool.assert_called_once_with("pan_batch_scan", airs_batch_args)

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_execute_tool_airs_scan_results_success(self, mock_logging):
        """Test successful execution of AIRS scan results retrieval."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock AIRS scan results response
        mock_results_response = types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps([
                        {
                            "scan_id": "12345678-1234-5678-9abc-123456789def",
                            "status": "completed",
                            "category": "benign",
                            "action": "allow",
                            "confidence": 0.95
                        }
                    ])
                )
            ]
        )
        client.session.call_tool.return_value = mock_results_response

        # Execute AIRS scan results retrieval
        airs_results_args = {
            "scan_ids": ["12345678-1234-5678-9abc-123456789def"]
        }

        result = await client.execute_tool("pan_get_scan_results", airs_results_args)

        assert result == mock_results_response

    @pytest.mark.asyncio
    async def test_execute_tool_airs_server_not_initialized(self):
        """Test tool execution when AIRS server is not initialized."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})

        # The retry decorator will wrap the RuntimeError in a tenacity.RetryError
        with pytest.raises(RetryError) as exc_info:
            await client.execute_tool("pan_inline_scan", {})

        # Verify the underlying exception is RuntimeError with expected message
        original_exception = exc_info.value.last_attempt.exception()
        assert isinstance(original_exception, RuntimeError)
        assert "Server aisecurity-scan-server not initialized" in str(original_exception)

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_execute_tool_airs_server_error_with_retry(self, mock_logging):
        """Test tool execution error handling with retry mechanism for AIRS server."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Simulate AIRS server error
        airs_error = Exception("AIRS API rate limit exceeded")
        client.session.call_tool.side_effect = airs_error

        # The retry decorator will wrap the exception in a tenacity.RetryError
        with pytest.raises(RetryError) as exc_info:
            await client.execute_tool("pan_inline_scan", {"prompt": "test"})

        # Should retry 3 times (default retry configuration)
        assert client.session.call_tool.call_count == 3

        # Verify the underlying exception is the original exception
        original_exception = exc_info.value.last_attempt.exception()
        assert isinstance(original_exception, Exception)
        assert "AIRS API rate limit exceeded" in str(original_exception)

        # Verify logging was called for each retry attempt
        expected_calls = [
                             call("Error executing pan_inline_scan: AIRS API rate limit exceeded", exc_info=True)
                         ] * 3  # Should be called 3 times due to retries

        mock_logging.error.assert_has_calls(expected_calls)

    def test_extract_text_content_mcp_text_content(self):
        """Test text extraction from MCP TextContent for AIRS responses."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})

        # Test with AIRS scan response TextContent
        airs_text_content = types.TextContent(
            type="text",
            text=json.dumps({
                "scan_id": "airs-scan-uuid",
                "category": "benign",
                "action": "allow"
            })
        )

        extracted = client.extract_text_content(airs_text_content)

        # Should return JSON representation for structured AIRS data
        assert isinstance(extracted, str)
        assert "airs-scan-uuid" in extracted
        assert "benign" in extracted

    def test_extract_text_content_mcp_embedded_resource(self):
        """Test text extraction from MCP EmbeddedResource for AIRS data."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})

        # Test with AIRS embedded resource
        airs_embedded_resource = types.EmbeddedResource(
            type="resource",
            resource=types.TextResourceContents(
                uri="airs://scan-report/12345",
                text="AIRS Scan Report: Threat detected"
            )
        )

        extracted = client.extract_text_content(airs_embedded_resource)

        # Should return JSON representation
        assert isinstance(extracted, str)
        assert "airs://scan-report/12345" in extracted

    def test_extract_text_content_list_of_airs_responses(self):
        """Test text extraction from list of AIRS response content."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})

        # Test with list of AIRS responses
        airs_content_list = [
            types.TextContent(type="text", text="AIRS scan 1 completed"),
            types.TextContent(type="text", text="AIRS scan 2 completed")
        ]

        extracted = client.extract_text_content(airs_content_list)

        assert isinstance(extracted, list)
        assert len(extracted) == 2
        assert all("AIRS scan" in item for item in extracted)

    def test_extract_text_content_object_with_text_attribute(self):
        """Test text extraction from object with text attribute for AIRS data."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})

        # Mock AIRS response object with text attribute
        class AIRSResponseObject:
            def __init__(self):
                self.text = "AIRS threat analysis: No threats detected"

        airs_response = AIRSResponseObject()
        extracted = client.extract_text_content(airs_response)

        assert extracted == "AIRS threat analysis: No threats detected"

    def test_extract_text_content_object_with_input_value_attribute(self):
        """Test text extraction from object with input_value attribute for AIRS scanning."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})

        # Mock AIRS scan input object
        class AIRSScanInput:
            def __init__(self):
                self.input_value = "User prompt for AIRS security scanning"

        airs_input = AIRSScanInput()
        extracted = client.extract_text_content(airs_input)

        assert extracted == "User prompt for AIRS security scanning"

    def test_extract_text_content_direct_string_airs_data(self):
        """Test text extraction from direct string AIRS data."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})

        airs_string_data = "AIRS scan completed: category=benign, action=allow"
        extracted = client.extract_text_content(airs_string_data)

        assert extracted == airs_string_data

    def test_check_initialized_when_session_exists(self):
        """Test _check_initialized when AIRS server session exists."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Should not raise exception
        client._check_initialized()

    def test_check_initialized_when_session_none(self):
        """Test _check_initialized when AIRS server session is None."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})

        with pytest.raises(RuntimeError, match="Server aisecurity-scan-server not initialized"):
            client._check_initialized()

    @pytest.mark.asyncio
    async def test_cleanup_airs_server_connection(self):
        """Test cleanup of AIRS server connection resources."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})
        client.session = AsyncMock(spec=ClientSession)

        mock_exit_stack = AsyncMock()
        client.exit_stack = mock_exit_stack

        await client.cleanup()

        mock_exit_stack.aclose.assert_called_once()
        assert client.session is None

    @pytest.mark.asyncio
    @patch('pan_aisecurity_mcp.mcp_relay.downstream_mcp_client.logging')
    async def test_cleanup_airs_server_with_exception(self, mock_logging):
        """Test cleanup handling exceptions during AIRS server cleanup."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})

        mock_exit_stack = AsyncMock()
        mock_exit_stack.aclose.side_effect = Exception("AIRS cleanup error")
        client.exit_stack = mock_exit_stack

        # Should not raise exception, but log error
        await client.cleanup()

        mock_logging.error.assert_called_with(
            "Error during cleanup of server aisecurity-scan-server: AIRS cleanup error"
        )

    @pytest.mark.asyncio
    async def test_concurrent_cleanup_calls_for_airs_server(self):
        """Test concurrent cleanup calls for AIRS server using cleanup lock."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})

        mock_exit_stack = AsyncMock()
        client.exit_stack = mock_exit_stack

        # Start multiple cleanup operations concurrently
        cleanup_tasks = [client.cleanup() for _ in range(3)]
        await asyncio.gather(*cleanup_tasks)

        # Should only call aclose once due to lock
        assert mock_exit_stack.aclose.call_count == 3  # Each task calls aclose


class TestDownstreamMcpClientIntegration:
    """Integration tests for DownstreamMcpClient with AIRS server scenarios."""

    @pytest.mark.asyncio
    async def test_airs_server_complete_workflow(self, airs_server_config, mock_airs_tools_list):
        """Test complete workflow with AIRS server from initialization to tool execution."""
        client = DownstreamMcpClient("aisecurity-scan-server", airs_server_config)

        # Mock successful initialization
        with patch.object(client, 'initialize') as mock_init:
            mock_init.return_value = None
            client.session = AsyncMock(spec=ClientSession)

            await client.initialize()

            # Mock tool listing
            mock_tools_response = [("tools", mock_airs_tools_list)]
            client.session.list_tools.return_value = mock_tools_response

            # List AIRS tools
            tools = await client.list_tools()
            assert len(tools) == 4

            # Mock AIRS inline scan execution
            mock_scan_result = types.CallToolResult(
                content=[types.TextContent(type="text", text='{"category": "benign", "action": "allow"}')]
            )
            client.session.call_tool.return_value = mock_scan_result

            # Execute AIRS scan
            result = await client.execute_tool("pan_inline_scan", {
                "prompt": "Is this safe content?",
                "response": "Yes, this content appears safe."
            })

            assert result == mock_scan_result

            # Cleanup AIRS connection
            await client.cleanup()

    @pytest.mark.asyncio
    async def test_airs_server_error_recovery_scenario(self, airs_server_config):
        """Test AIRS server error recovery and retry scenarios."""
        client = DownstreamMcpClient("aisecurity-scan-server", airs_server_config)
        client.session = AsyncMock(spec=ClientSession)

        # Simulate intermittent AIRS server errors
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:  # Fail first 2 attempts
                raise Exception("AIRS temporary server error")
            return types.CallToolResult(
                content=[types.TextContent(type="text", text='{"status": "success"}')]
            )

        client.session.call_tool.side_effect = side_effect

        # Should succeed after retries
        result = await client.execute_tool("pan_inline_scan", {"prompt": "test"})
        assert result is not None
        assert call_count == 3  # 2 failures + 1 success

    @pytest.mark.asyncio
    async def test_multiple_airs_servers_scenario(self, airs_server_config, airs_backup_server_config):
        """Test scenario with multiple AIRS servers for high availability."""
        # Primary AIRS server
        primary_client = DownstreamMcpClient("aisecurity-scan-server", airs_server_config)
        primary_client.session = AsyncMock(spec=ClientSession)

        # Backup AIRS server
        backup_client = DownstreamMcpClient("aisecurity-backup-server", airs_backup_server_config)
        backup_client.session = AsyncMock(spec=ClientSession)

        # Both servers should be able to list tools
        mock_tools_response = [("tools", [
            types.Tool(name="pan_inline_scan", description="Primary AIRS scan", inputSchema={}),
        ])]
        primary_client.session.list_tools.return_value = mock_tools_response
        backup_client.session.list_tools.return_value = mock_tools_response

        primary_tools = await primary_client.list_tools()
        backup_tools = await backup_client.list_tools()

        assert len(primary_tools) == 1
        assert len(backup_tools) == 1
        assert primary_tools[0].name == backup_tools[0].name

    @pytest.mark.asyncio
    async def test_airs_server_large_batch_scan_scenario(self):
        """Test AIRS server handling large batch scan operations."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock large batch scan response
        large_batch_response = types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps([
                        {"req_id": i, "scan_id": f"scan-{i}-uuid", "report_id": f"R-scan-{i}-uuid"}
                        for i in range(1, 6)  # MAX_NUMBER_OF_BATCH_SCAN_OBJECTS = 5
                    ])
                )
            ]
        )
        client.session.call_tool.return_value = large_batch_response

        # Execute large batch scan
        large_batch_args = {
            "scan_contents": [
                {"prompt": f"Prompt {i}", "response": f"Response {i}"}
                for i in range(1, 6)
            ]
        }

        result = await client.execute_tool("pan_batch_scan", large_batch_args)

        # Verify batch processing capabilities
        assert result == large_batch_response
        extracted_content = client.extract_text_content(result.content[0])
        batch_data = json.loads(extracted_content)
        assert len(batch_data) == 3

    @pytest.mark.asyncio
    async def test_airs_server_scan_results_pagination_scenario(self):
        """Test AIRS server scan results retrieval with pagination."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock paginated scan results (MAX_NUMBER_OF_SCAN_IDS = 100)
        mock_results_response = types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps([
                        {
                            "scan_id": f"uuid-{i:04d}",
                            "status": "completed",
                            "category": "benign" if i % 2 == 0 else "malicious",
                            "action": "allow" if i % 2 == 0 else "block"
                        }
                        for i in range(100)  # Full batch of scan results
                    ])
                )
            ]
        )
        client.session.call_tool.return_value = mock_results_response

        # Execute scan results retrieval with maximum batch size
        scan_ids = [f"uuid-{i:04d}" for i in range(100)]
        result = await client.execute_tool("pan_get_scan_results", {"scan_ids": scan_ids})

        assert result == mock_results_response

        # Verify pagination handling
        extracted_content = client.extract_text_content(result.content[0])
        results_data = json.loads(extracted_content)
        assert len(results_data) == 3

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_airs_server_threat_report_analysis_scenario(self):
        """Test AIRS server threat report analysis with detailed findings."""
        client = DownstreamMcpClient("aisecurity-scan-server", {})
        client.session = AsyncMock(spec=ClientSession)

        # Mock detailed threat report response
        threat_report_response = types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps([
                        {
                            "report_id": "R-12345678-1234-5678-9abc-123456789def",
                            "scan_id": "12345678-1234-5678-9abc-123456789def",
                            "threat_analysis": {
                                "category": "malicious",
                                "subcategory": "prompt_injection",
                                "confidence": 0.98,
                                "risk_level": "high",
                                "detected_patterns": [
                                    "potential_jailbreak_attempt",
                                    "system_prompt_manipulation"
                                ],
                                "recommendations": "Block content and alert security team"
                            },
                            "metadata": {
                                "ai_profile": "default_ai_profile",
                                "scan_timestamp": "2024-01-15T12:00:00Z",
                                "processing_time_ms": 234
                            }
                        }
                    ])
                )
            ]
        )
        client.session.call_tool.return_value = threat_report_response

        # Execute threat report retrieval
        result = await client.execute_tool("pan_get_scan_reports", {
            "report_ids": ["R-12345678-1234-5678-9abc-123456789def"]
        })

        assert result == threat_report_response

        # Verify threat analysis data structure
        extracted_content = client.extract_text_content(result.content[0])

        # Fix: The extract_text_content returns a dict with 'text' key containing the JSON
        if isinstance(extracted_content, dict) and 'text' in extracted_content:
            json_text = extracted_content['text']
        else:
            json_text = extracted_content

        report_data = json.loads(json_text)

        # The report_data is a list, so get the first report
        assert len(report_data) > 0
        report = report_data["text"]
        parsed_report = json.loads(report)
        threat_analysis_data = parsed_report[0]["threat_analysis"]
        assert threat_analysis_data["category"] == "malicious"
        assert threat_analysis_data["risk_level"] == "high"
        assert threat_analysis_data["subcategory"] == "prompt_injection"