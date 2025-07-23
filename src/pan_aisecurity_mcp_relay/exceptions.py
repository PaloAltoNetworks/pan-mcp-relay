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

from enum import Enum
from typing import Optional

import mcp.types as types


class ErrorType(Enum):
    """Enum defining error type codes for AISecMcpRelay exceptions.

    These error types are used to categorize different errors that can occur
    within the SDK and are included in exception messages.
    """

    AISEC_MCP_RELAY_INTERNAL_ERROR = "AISEC_MCP_RELAY_INTERNAL_ERROR"
    INVALID_CONFIGURATION = "AISEC_INVALID_CONFIGURATION"
    TOOL_EXECUTION_ERROR = "AISEC_TOOL_EXECUTION_ERROR"
    SECURITY_BLOCK = "AISEC_SECURITY_BLOCK"
    TOOL_NOT_FOUND = "AISEC_TOOL_NOT_FOUND"
    SERVER_NOT_FOUND = "AISEC_SERVER_NOT_FOUND"
    VALIDATION_ERROR = "AISEC_VALIDATION_ERROR"
    TOOL_REGISTRY_ERROR = "AISEC_TOOL_REGISTRY_ERROR"


class AISecMcpRelayException(Exception):
    """Base exception class for mcp-relay-related exceptions."""

    def __init__(self, message: str = "", error_type: Optional[ErrorType] = None) -> None:
        self.message = message
        self.error_type = error_type

    def __str__(self) -> str:
        if self.error_type:
            return f"{self.error_type.value}:{self.message}"
        return f"{self.message}"

    def to_mcp_format(self) -> types.CallToolResult:
        """
        Convert the exception to an MCP call tool result format.

        Returns:
            types.CallToolResult: A structured error result
        """
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=self.__str__())])
