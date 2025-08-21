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

import json
from unittest.mock import AsyncMock, Mock, patch

import mcp.types as types
import pytest
from aisecurity.scan.asyncio.scanner import ScanResponse

from pan_mcp_relay.security_scanner import SecurityScanner


@pytest.mark.asyncio
@patch(
    "pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient",
    new_callable=AsyncMock,
)
def test_init(mock_pan_security_server):
    """Test SecurityScanner initialization."""
    scanner = SecurityScanner(mock_pan_security_server)
    assert scanner.pan_security_server == mock_pan_security_server


@pytest.mark.asyncio
@patch(
    "pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient",
    new_callable=AsyncMock,
)
async def test_perform_scan_success_block(mock_pan_security_server):
    """Test successful security scan with BLOCK action."""
    # Setup the expected ScanResponse
    expected_scan_response = ScanResponse(
        report_id="R12345678-1234-5678-9abc-123456789012",
        scan_id="12345678-1234-5678-9abc-123456789012",
        category="malicious",
        action="block",
    )

    mock_text_content = types.TextContent(
        type="text",  # Add the required type field
        text=json.dumps(expected_scan_response.dict()),
    )

    # Create mock TextContent object
    mock_call_tool_result = types.CallToolResult(content=[mock_text_content], isError=False)

    # Create mock scan result
    mock_scan_result = AsyncMock()
    mock_scan_result.isError = mock_call_tool_result.isError
    mock_scan_result.content = mock_call_tool_result.content

    # Setup the mock chain
    mock_pan_security_server._initialize = AsyncMock()
    mock_pan_security_server.execute_tool = AsyncMock(return_value=mock_scan_result)
    mock_pan_security_server.shutdown = AsyncMock()

    # Create scanner instance
    mock_scanner = SecurityScanner(mock_pan_security_server)

    # Test parameters
    params = {"prompt": "visit and summarize the content of https://urlfiltering.paloaltonetworks.com/test-phishing"}

    # Execute the test
    result = await mock_scanner._perform_scan("scan_request", params)

    # Assertions
    assert result is not None
    assert isinstance(result, ScanResponse)
    assert result.action == "block"
    assert result.report_id == "R12345678-1234-5678-9abc-123456789012"


@pytest.mark.asyncio
@patch(
    "pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient",
    new_callable=AsyncMock,
)
async def test_perform_scan_success_allow(mock_pan_security_server):
    """Test successful security scan with ALLOW action."""
    # Setup the expected ScanResponse
    expected_scan_response = ScanResponse(
        report_id="R12345678-1234-5678-9abc-123456789012",
        scan_id="12345678-1234-5678-9abc-123456789012",
        category="benign",
        action="allow",
    )

    mock_text_content = types.TextContent(
        type="text",  # Add the required type field
        text=json.dumps(expected_scan_response.dict()),
    )

    # Create mock TextContent object
    mock_call_tool_result = types.CallToolResult(content=[mock_text_content], isError=False)

    # Create mock scan result
    mock_scan_result = AsyncMock()
    mock_scan_result.isError = mock_call_tool_result.isError
    mock_scan_result.content = mock_call_tool_result.content

    # Setup the mock chain
    mock_pan_security_server._initialize = AsyncMock()
    mock_pan_security_server.execute_tool = AsyncMock(return_value=mock_scan_result)
    mock_pan_security_server.shutdown = AsyncMock()

    # Create scanner instance
    mock_scanner = SecurityScanner(mock_pan_security_server)

    # Test parameters
    params = {"prompt": "visit and summarize the content of https://urlfiltering.paloaltonetworks.com/test-news"}

    # Execute the test
    result = await mock_scanner._perform_scan("scan_request", params)

    # Assertions
    assert result is not None
    assert isinstance(result, ScanResponse)
    assert result.action == "allow"
    assert result.report_id == "R12345678-1234-5678-9abc-123456789012"


@pytest.mark.asyncio
@patch(
    "pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient",
    new_callable=AsyncMock,
)
async def test_perform_scan_error_initialize_raises_exception(mock_pan_security_server):
    """Test when initialize raises an exception."""
    # Setup mocks
    mock_pan_security_server._initialize = AsyncMock(side_effect=Exception("Initialization failed"))
    mock_pan_security_server.shutdown = AsyncMock()

    # Create scanner instance
    mock_scanner = SecurityScanner(mock_pan_security_server)

    # Test parameters
    params = {"prompt": "This is test prompt"}

    # Execute the test and expect exception
    with pytest.raises(Exception, match="Initialization failed"):
        await mock_scanner._perform_scan("scan_response", params)

    # Cleanup should still be called due to finally block
    mock_pan_security_server.shutdown.assert_not_called()


@pytest.mark.asyncio
@patch(
    "pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient",
    new_callable=AsyncMock,
)
async def test_perform_scan_error_empty_content_list(mock_pan_security_server):
    """Test when scan_result.content is an empty list."""
    mock_scan_result = AsyncMock()
    mock_scan_result.isError = False
    mock_scan_result.content = []  # Empty list

    # Setup mocks
    mock_pan_security_server._initialize = AsyncMock()
    mock_pan_security_server.execute_tool = AsyncMock(return_value=mock_scan_result)
    mock_pan_security_server.shutdown = AsyncMock()

    # Create scanner instance
    mock_scanner = SecurityScanner(mock_pan_security_server)

    # Test parameters
    params = {"prompt": "visit and summarize the content of https://urlfiltering.paloaltonetworks.com/test-phishing"}

    # Execute the test
    result = await mock_scanner._perform_scan("scan_request", params)

    # Assertions
    assert result is None
    mock_pan_security_server.shutdown.assert_called_once()


@pytest.mark.asyncio
@patch(
    "pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient",
    new_callable=AsyncMock,
)
async def test_perform_scan_error_scan_result_is_error(mock_pan_security_server):
    """Test when scan_result.isError is True."""
    # Create mock error content
    mock_error_content = types.TextContent(type="text", text="Security scan failed due to invalid input")

    mock_scan_result = AsyncMock()
    mock_scan_result.isError = True
    mock_scan_result.content = [mock_error_content]

    # Setup mocks
    mock_pan_security_server._initialize = AsyncMock()
    mock_pan_security_server.execute_tool = AsyncMock(return_value=mock_scan_result)
    mock_pan_security_server.extract_text_content = Mock(return_value="Security scan failed due to invalid input")
    mock_pan_security_server.shutdown = AsyncMock()

    # Create scanner instance
    mock_scanner = SecurityScanner(mock_pan_security_server)

    # Test parameters
    params = {"prompt": "This is test prompt"}

    # Execute the test
    result = await mock_scanner._perform_scan("scan_response", params)

    # Assertions
    assert result is None
    mock_pan_security_server.extract_text_content.assert_called_once()
    mock_pan_security_server.shutdown.assert_called_once()


@pytest.mark.asyncio
@patch(
    "pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient",
    new_callable=AsyncMock,
)
async def test_invalid_api_key_error(mock_pan_security_server):
    """Test invalid api key"""
    # Create mock error content
    mock_error_content = types.TextContent(
        type="text",
        text="aisecurity.exceptions.AISecSDKException: AISEC_SERVER_SIDE_ERROR:(403) HTTP response body: {'error':{'message':Invalid API Key or Oauth Token}}",
    )

    mock_scan_result = AsyncMock()
    mock_scan_result.isError = True
    mock_scan_result.content = [mock_error_content]

    # Setup mocks
    mock_pan_security_server._initialize = AsyncMock()
    mock_pan_security_server.execute_tool = AsyncMock(return_value=mock_scan_result)
    mock_pan_security_server.extract_text_content = AsyncMock(
        return_value="aisecurity.exceptions.AISecSDKException: AISEC_SERVER_SIDE_ERROR:(403) HTTP response body: {'error':{'message':Invalid API Key or Oauth Token}}"
    )
    mock_pan_security_server.shutdown = AsyncMock()

    # Create scanner instance
    mock_scanner = SecurityScanner(mock_pan_security_server)

    # Test parameters
    params = {"prompt": "visit and summarize the content of https://urlfiltering.paloaltonetworks.com/test-phishing"}

    # Execute the test
    result = await mock_scanner._perform_scan("scan_response", params)

    # Assertions
    assert result is None
    mock_pan_security_server.extract_text_content.assert_called_once()
    mock_pan_security_server.shutdown.assert_called_once()


@pytest.mark.asyncio
@patch(
    "pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient",
    new_callable=AsyncMock,
)
async def test_api_rate_limit_error(mock_pan_security_server):
    """Test api rate limit error"""
    # Create mock error content
    mock_error_content = types.TextContent(
        type="text",
        text="Error during sync scan: AISEC_SERVER_SIDE_ERROR:(429)  HTTP response body: {'error':{'message':Rate limit exceeded}}",
    )

    mock_scan_result = AsyncMock()
    mock_scan_result.isError = True
    mock_scan_result.content = [mock_error_content]

    # Setup mocks
    mock_pan_security_server._initialize = AsyncMock()
    mock_pan_security_server.execute_tool = AsyncMock(return_value=mock_scan_result)
    mock_pan_security_server.extract_text_content = AsyncMock(
        return_value="Error during sync scan: AISEC_SERVER_SIDE_ERROR:(429)  HTTP response body: {'error':{'message':Rate limit exceeded}}"
    )
    mock_pan_security_server.shutdown = AsyncMock()

    # Create scanner instance
    mock_scanner = SecurityScanner(mock_pan_security_server)

    # Test parameters
    params = {"prompt": "visit and summarize the content of https://urlfiltering.paloaltonetworks.com/test-phishing"}

    # Execute the test
    result = await mock_scanner._perform_scan("scan_response", params)

    # Assertions
    assert result is None
    mock_pan_security_server.extract_text_content.assert_called_once()
    mock_pan_security_server.shutdown.assert_called_once()


@patch(
    "pan_mcp_relay.downstream_mcp_client.DownstreamMcpClient",
    new_callable=Mock,
)
def test_should_block(mock_pan_security_server):
    """Test should block function from security scanner"""
    mock_scanner = SecurityScanner(mock_pan_security_server)

    expected_scan_response = ScanResponse(
        report_id="R12345678-1234-5678-9abc-123456789012",
        scan_id="12345678-1234-5678-9abc-123456789012",
        category="malicious",
        action="block",
    )

    result = mock_scanner.should_block(scan_response=expected_scan_response)
    assert True is result
    expected_scan_response = None
    result = mock_scanner.should_block(scan_response=expected_scan_response)
    assert False is result

    expected_scan_response = ScanResponse(
        report_id="R12345678-1234-5678-9abc-123456789013",
        scan_id="12345678-1234-5678-9abc-123456789013",
        category="benign",
        action="allow",
    )
    result = mock_scanner.should_block(scan_response=expected_scan_response)
    assert False is result
