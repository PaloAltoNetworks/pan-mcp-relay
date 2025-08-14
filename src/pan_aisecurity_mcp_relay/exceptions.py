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


class AISecMcpRelayBaseException(Exception):
    """Base exception class for mcp-relay-related exceptions."""

    def __init__(self, message: str = "") -> None:
        self.message = message

    # def __str__(self) -> str:
    #     return f"{self.__class__.__name__}:{self.message}"

    def to_mcp_format(self) -> types.CallToolResult:
        """
        Convert the exception to an MCP call tool result format.

        Returns:
            types.CallToolResult: A structured error result
        """
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=str(self))])


class AISecMcpRelayInternalError(AISecMcpRelayBaseException):
    """Exception for internal errors."""


class AISecMcpRelayInvalidConfigurationError(AISecMcpRelayBaseException):
    """Exception for invalid configuration errors."""


class AISecMcpRelayToolExecutionError(AISecMcpRelayBaseException):
    """Exception for tool execution errors."""


class AISecMcpRelaySecurityBlockError(AISecMcpRelayBaseException):
    """Exception for security block errors."""


class AISecMcpRelayToolNotFoundError(AISecMcpRelayBaseException):
    """Exception for tool not found errors."""


class AISecMcpRelayServerNotFoundError(AISecMcpRelayBaseException):
    """Exception for server not found errors."""


class AISecMcpRelayValidationError(AISecMcpRelayBaseException):
    """Exception for validation errors."""


class AISecMcpRelayToolRegistryError(AISecMcpRelayBaseException):
    """Exception for tool registry errors."""
