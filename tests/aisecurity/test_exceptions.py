import unittest
from enum import Enum
import mcp.types as types
from pan_aisecurity_mcp.mcp_relay.exceptions import ErrorType, AISecMcpRelayException


class TestErrorType(unittest.TestCase):
    """Test cases for ErrorType enum."""

    def test_error_type_values(self):
        """Test that all ErrorType enum values are correct."""
        expected_values = {
            "AISEC_MCP_RELAY_INTERNAL_ERROR": "AISEC_MCP_RELAY_INTERNAL_ERROR",
            "INVALID_CONFIGURATION": "AISEC_INVALID_CONFIGURATION",
            "TOOL_EXECUTION_ERROR": "AISEC_TOOL_EXECUTION_ERROR",
            "SECURITY_BLOCK": "AISEC_SECURITY_BLOCK",
            "TOOL_NOT_FOUND": "AISEC_TOOL_NOT_FOUND",
            "SERVER_NOT_FOUND": "AISEC_SERVER_NOT_FOUND",
            "VALIDATION_ERROR": "AISEC_VALIDATION_ERROR",
            "TOOL_REGISTRY_ERROR": "AISEC_TOOL_REGISTRY_ERROR"
        }

        for attr_name, expected_value in expected_values.items():
            with self.subTest(error_type=attr_name):
                self.assertTrue(hasattr(ErrorType, attr_name))
                self.assertEqual(getattr(ErrorType, attr_name).value, expected_value)

    def test_error_type_count(self):
        """Test that we have the expected number of error types."""
        self.assertEqual(len(ErrorType), 8)

    def test_error_type_enum_members(self):
        """Test that ErrorType is properly defined as enum."""
        self.assertTrue(issubclass(ErrorType, Enum))

        # Test specific enum members
        self.assertIn(ErrorType.AISEC_MCP_RELAY_INTERNAL_ERROR, ErrorType)
        self.assertIn(ErrorType.INVALID_CONFIGURATION, ErrorType)
        self.assertIn(ErrorType.TOOL_EXECUTION_ERROR, ErrorType)
        self.assertIn(ErrorType.SECURITY_BLOCK, ErrorType)
        self.assertIn(ErrorType.TOOL_NOT_FOUND, ErrorType)
        self.assertIn(ErrorType.SERVER_NOT_FOUND, ErrorType)
        self.assertIn(ErrorType.VALIDATION_ERROR, ErrorType)
        self.assertIn(ErrorType.TOOL_REGISTRY_ERROR, ErrorType)


class TestAISecMcpRelayException(unittest.TestCase):
    """Test cases for AISecMcpRelayException class."""

    def test_init_with_message_only(self):
        """Test exception initialization with message only."""
        message = "Test error message"
        exception = AISecMcpRelayException(message)

        self.assertEqual(exception.message, message)
        self.assertIsNone(exception.error_type)

    def test_init_with_message_and_error_type(self):
        """Test exception initialization with message and error type."""
        message = "Configuration is invalid"
        error_type = ErrorType.INVALID_CONFIGURATION
        exception = AISecMcpRelayException(message, error_type)

        self.assertEqual(exception.message, message)
        self.assertEqual(exception.error_type, error_type)

    def test_init_with_empty_message(self):
        """Test exception initialization with empty message."""
        exception = AISecMcpRelayException()

        self.assertEqual(exception.message, "")
        self.assertIsNone(exception.error_type)

    def test_init_with_error_type_only(self):
        """Test exception initialization with error type but no message."""
        error_type = ErrorType.TOOL_NOT_FOUND
        exception = AISecMcpRelayException(error_type=error_type)

        self.assertEqual(exception.message, "")
        self.assertEqual(exception.error_type, error_type)

    def test_str_with_message_only(self):
        """Test string representation with message only."""
        message = "Something went wrong"
        exception = AISecMcpRelayException(message)

        self.assertEqual(str(exception), message)

    def test_str_with_message_and_error_type(self):
        """Test string representation with message and error type."""
        message = "Tool execution failed"
        error_type = ErrorType.TOOL_EXECUTION_ERROR
        exception = AISecMcpRelayException(message, error_type)

        expected = f"{error_type.value}:{message}"
        self.assertEqual(str(exception), expected)

    def test_str_with_error_type_only(self):
        """Test string representation with error type but no message."""
        error_type = ErrorType.SECURITY_BLOCK
        exception = AISecMcpRelayException(error_type=error_type)

        expected = f"{error_type.value}:"
        self.assertEqual(str(exception), expected)

    def test_str_with_empty_message_and_no_error_type(self):
        """Test string representation with empty message and no error type."""
        exception = AISecMcpRelayException()

        self.assertEqual(str(exception), "")

    def test_to_mcp_format_with_message_and_error_type(self):
        """Test to_mcp_format method with message and error type."""
        message = "Server not found"
        error_type = ErrorType.SERVER_NOT_FOUND
        exception = AISecMcpRelayException(message, error_type)

        result = exception.to_mcp_format()

        # Verify return type

        self.assertIsInstance(result, types.CallToolResult)

        # Verify isError is True
        self.assertTrue(result.isError)

        # Verify content structure
        self.assertIsInstance(result.content, list)
        self.assertEqual(len(result.content), 1)

        # Verify content item
        content_item = result.content[0]
        self.assertIsInstance(content_item, types.TextContent)
        self.assertEqual(content_item.type, "text")
        self.assertEqual(content_item.text, f"{error_type.value}:{message}")


    def test_to_mcp_format_with_message_only(self):
        """Test to_mcp_format method with message only."""
        message = "Generic error occurred"
        exception = AISecMcpRelayException(message)

        result = exception.to_mcp_format()

        # Verify return type and structure
        self.assertIsInstance(result, types.CallToolResult)
        self.assertTrue(result.isError)
        self.assertIsInstance(result.content, list)
        self.assertEqual(len(result.content), 1)

        # Verify content
        content_item = result.content[0]
        self.assertIsInstance(content_item, types.TextContent)
        self.assertEqual(content_item.type, "text")
        self.assertEqual(content_item.text, message)

    def test_to_mcp_format_with_empty_exception(self):
        """Test to_mcp_format method with empty exception."""
        exception = AISecMcpRelayException()

        result = exception.to_mcp_format()

        # Verify return type and structure
        self.assertIsInstance(result, types.CallToolResult)
        self.assertTrue(result.isError)
        self.assertIsInstance(result.content, list)
        self.assertEqual(len(result.content), 1)

        # Verify content
        content_item = result.content[0]
        self.assertIsInstance(content_item, types.TextContent)
        self.assertEqual(content_item.type, "text")
        self.assertEqual(content_item.text, "")

    def test_exception_can_be_raised_and_caught(self):
        """Test that the exception can be properly raised and caught."""
        message = "Test exception"
        error_type = ErrorType.VALIDATION_ERROR

        with self.assertRaises(AISecMcpRelayException) as context:
            raise AISecMcpRelayException(message, error_type)

        caught_exception = context.exception
        self.assertEqual(caught_exception.message, message)
        self.assertEqual(caught_exception.error_type, error_type)
        self.assertEqual(str(caught_exception), f"{error_type.value}:{message}")

    def test_all_error_types_work_with_exception(self):
        """Test that all ErrorType enum values work with the exception."""
        message = "Test message"

        for error_type in ErrorType:
            with self.subTest(error_type=error_type):
                exception = AISecMcpRelayException(message, error_type)

                self.assertEqual(exception.error_type, error_type)
                self.assertEqual(exception.message, message)

                expected_str = f"{error_type.value}:{message}"
                self.assertEqual(str(exception), expected_str)

                # Test MCP format
                mcp_result = exception.to_mcp_format()
                self.assertTrue(mcp_result.isError)
                self.assertEqual(mcp_result.content[0].text, expected_str)


if __name__ == '__main__':
    unittest.main()
