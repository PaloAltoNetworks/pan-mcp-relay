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

import mcp.types as types

from pan_mcp_relay.exceptions import McpRelayBaseError, McpRelayServerNotFoundError

"""Test cases for AISecMcpRelayException class."""


def test_init_with_message_only():
    """Test exception initialization with message only."""
    message = "Test error message"
    exception = McpRelayBaseError(message)

    assert exception.message == message


def test_init_with_empty_message():
    """Test exception initialization with empty message."""
    exception = McpRelayBaseError()

    assert exception.message == ""


def test_str_with_message_only():
    """Test string representation with message only."""
    message = "Something went wrong"
    exception = McpRelayBaseError(message)

    assert str(exception) == f"{message}"


def test_to_mcp_format_with_message_and_error_type():
    """Test to_mcp_format method with message and error type."""
    message = "Server not found"
    exception = McpRelayServerNotFoundError(message)

    result = exception.to_mcp_format()

    # Verify return type
    assert isinstance(result, types.CallToolResult)

    # Verify isError is True
    assert result.isError is True

    # Verify content structure
    assert isinstance(result.content, list)
    assert len(result.content) == 1

    # Verify content item
    content_item = result.content[0]
    assert isinstance(content_item, types.TextContent)
    assert content_item.type == "text"
    assert content_item.text == "Server not found"
