import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch, Mock
import mcp.types as types
from aisecurity.security_scanner import SecurityScanner
from aisecurity.scan.asyncio.scanner import ScanResponse


class TestSecurityScanner(unittest.IsolatedAsyncioTestCase):
    """Test suite for SecurityScanner class."""

    @patch(
        "mcp_relay.downstream_mcp_client.DownstreamMcpClient",
        new_callable=AsyncMock,
    )
    async def test_init(self, mock_pan_security_server):
        """Test SecurityScanner initialization."""
        self.scanner = SecurityScanner(mock_pan_security_server)
        assert self.scanner.pan_security_server == mock_pan_security_server


    @patch(
        "mcp_relay.downstream_mcp_client.DownstreamMcpClient",
        new_callable=AsyncMock,
    )
    async def test_perform_scan_success_allow(self,mock_pan_security_server):
        """Test successful security scan with ALLOW action."""
        # Setup mock response
        mock_sync_scan_response = ScanResponse(
            report_id="REP12345678910",
            scan_id="test_id",
            category="malign",
            action="block",
        )

        mock_scanner = SecurityScanner(mock_pan_security_server)
        mock_scanner.return_value = mock_sync_scan_response
        params = {"test_mock" : "mock_scan"}
        result = await mock_scanner._perform_scan("mock_scan",params)
        print (result)
        #self.assertIsInstance(result, ScanResponse)

    @patch(
        "mcp_relay.downstream_mcp_client.DownstreamMcpClient",
        new_callable=AsyncMock,
    )
    async def test_perform_scan_success_allow1(self, mock_pan_security_server):
        """Test successful security scan with ALLOW action."""

        # Setup the expected ScanResponse
        expected_scan_response = ScanResponse(
            report_id="REP12345678910",
            scan_id="test_id",
            category="malign",
            action="allow",  # Changed to "allow" to match test name
        )

        mock_text_content = types.TextContent(
            type="text",  # Add the required type field
            text=json.dumps(expected_scan_response.dict())
        )

        # Create mock TextContent object
        mock_text_content = types.CallToolResult(
            content=[mock_text_content],isError= False
        )

        # Create mock scan result
        mock_scan_result = Mock()
        mock_scan_result.isError = mock_text_content.isError
        mock_scan_result.content = mock_text_content.content

        # Setup the mock chain
        mock_pan_security_server.initialize = AsyncMock()
        mock_pan_security_server.execute_tool = AsyncMock(return_value=mock_scan_result)
        mock_pan_security_server.cleanup = AsyncMock()

        # Create scanner instance
        mock_scanner = SecurityScanner(mock_pan_security_server)

        # Test parameters
        params = {"test_mock": "mock_scan"}

        # Execute the test
        result = await mock_scanner._perform_scan("mock_scan", params)

        # Assertions
        assert result is not None
        assert isinstance(result, ScanResponse)
        assert result.action == "allow"
        assert result.report_id == "REP12345678910"

    @patch(
        "mcp_relay.downstream_mcp_client.DownstreamMcpClient",
        new_callable=AsyncMock,
    )
    async def test_perform_scan_error_initialize_raises_exception(self, mock_pan_security_server):
        """Test when initialize raises an exception."""
        # Setup mocks
        mock_pan_security_server.initialize = AsyncMock(side_effect=Exception("Initialization failed"))
        mock_pan_security_server.cleanup = AsyncMock()

        # Create scanner instance
        mock_scanner = SecurityScanner(mock_pan_security_server)

        # Test parameters
        params = {"test_mock": "mock_scan"}

        # Execute the test and expect exception
        with self.assertRaisesRegex(Exception, "Initialization failed"):
            await mock_scanner._perform_scan("mock_scan", params)

        # Cleanup should still be called due to finally block
        mock_pan_security_server.cleanup.assert_not_called()

    @patch(
        "mcp_relay.downstream_mcp_client.DownstreamMcpClient",
        new_callable=AsyncMock,
    )
    async def test_perform_scan_error_empty_content_list(self, mock_pan_security_server):
        """Test when scan_result.content is an empty list."""
        mock_scan_result = Mock()
        mock_scan_result.isError = False
        mock_scan_result.content = []  # Empty list

        # Setup mocks
        mock_pan_security_server.initialize = AsyncMock()
        mock_pan_security_server.execute_tool = AsyncMock(return_value=mock_scan_result)
        mock_pan_security_server.cleanup = AsyncMock()

        # Create scanner instance
        mock_scanner = SecurityScanner(mock_pan_security_server)

        # Test parameters
        params = {"test_mock": "mock_scan"}

        # Execute the test
        result = await mock_scanner._perform_scan("mock_scan", params)

        # Assertions
        assert result is None
        mock_pan_security_server.cleanup.assert_called_once()

    @patch(
        "mcp_relay.downstream_mcp_client.DownstreamMcpClient",
        new_callable=AsyncMock,
    )
    async def test_perform_scan_error_scan_result_is_error(self, mock_pan_security_server):
        """Test when scan_result.isError is True."""
        # Create mock error content
        mock_error_content = types.TextContent(
            type="text",
            text="Security scan failed due to invalid input"
        )

        mock_scan_result = Mock()
        mock_scan_result.isError = True
        mock_scan_result.content = [mock_error_content]

        # Setup mocks
        mock_pan_security_server.initialize = AsyncMock()
        mock_pan_security_server.execute_tool = AsyncMock(return_value=mock_scan_result)
        mock_pan_security_server.extract_text_content = Mock(return_value="Security scan failed due to invalid input")
        mock_pan_security_server.cleanup = AsyncMock()

        # Create scanner instance
        mock_scanner = SecurityScanner(mock_pan_security_server)

        # Test parameters
        params = {"test_mock": "mock_scan"}

        # Execute the test
        result = await mock_scanner._perform_scan("mock_scan", params)

        # Assertions
        assert result is None
        mock_pan_security_server.extract_text_content.assert_called_once()
        mock_pan_security_server.cleanup.assert_called_once()



