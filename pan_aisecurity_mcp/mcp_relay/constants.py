"""
Constants for MCP Relay application.

This module defines all constants used throughout the Pan AI Security MCP Relay system.
Constants are organized into logical groups for better maintainability and clarity.
"""

from datetime import datetime
from enum import Enum
from typing import Final


# =============================================================================
# SERVER IDENTIFICATION
# =============================================================================

SECURITY_SERVER_NAME: Final[str] = "pan-aisecurity"
"""Name identifier for the Pan AI Security server component."""

MCP_RELAY_NAME: Final[str] = "pan-aisecurity-relay"
"""Name identifier for the MCP relay server component."""


# =============================================================================
# TRANSPORT TYPES
# =============================================================================


class TransportType(str, Enum):
    """
    Enumeration of supported transport types for MCP communication.

    Attributes:
        STDIO: Standard input/output transport using subprocess pipes
        SSE: Server-Sent Events transport using HTTP streaming
    """

    STDIO = "stdio"
    SSE = "sse"

    def __str__(self) -> str:
        """Return the string representation of the transport type."""
        return self.value


# =============================================================================
# CONFIGURATION LABELS
# =============================================================================

ENVIRONMENT_CONFIG_LABEL: Final[str] = "env"
"""Label for environment configuration section in config files."""

MCP_SERVER_CONFIG_LABEL: Final[str] = "mcpServers"
"""Label for MCP servers configuration section in config files."""

HIDDEN_MODE_LABEL: Final[str] = "hidden_mode"
"""Configuration label for hidden mode setting."""

HIDDEN_MODE_ENABLED: Final[str] = "enabled"
"""Value indicating hidden mode is enabled."""


# =============================================================================
# DEFAULT VALUES AND LIMITS
# =============================================================================

TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT: Final[int] = 300
"""Default cache expiry time for tool registry in seconds (5 minutes)."""

MAX_DOWNSTREAM_SERVERS_DEFAULT: Final[int] = 32
"""Maximum number of downstream servers that can be configured."""

MAX_DOWNSTREAM_TOOLS_DEFAULT: Final[int] = 64
"""Maximum total number of tools across all servers."""


# =============================================================================
# TIME CONSTANTS
# =============================================================================

UNIX_EPOCH: Final[datetime] = datetime.fromtimestamp(0)
"""Unix epoch reference time (1970-01-01 00:00:00 UTC)."""


# =============================================================================
# TOOL NAMES
# =============================================================================

TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO: Final[str] = "list_downstream_servers_info"
"""Tool name for listing downstream server information."""

TOOL_NAME_PAN_AISECURITY_INLINE_SCAN: Final[str] = "pan_inline_scan"
"""Tool name for Pan AI Security inline scanning."""


# =============================================================================
# SECURITY SCAN CONSTANTS
# =============================================================================

EXPECTED_SECURITY_SCAN_RESULT_CONTENT_LENGTH: Final[int] = 1
"""Expected number of content items in security scan results."""

SECURITY_SCAN_RESPONSE_ACTION_BLOCK: Final[str] = "block"
"""Security scan response indicating content should be blocked."""

SECURITY_SCAN_RESPONSE_ACTION_ALLOW: Final[str] = "allow"
"""Security scan response indicating content is safe to proceed."""
