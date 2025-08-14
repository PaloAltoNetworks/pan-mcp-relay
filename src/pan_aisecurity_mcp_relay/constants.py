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

"""
Constants for MCP Relay application.

This module defines all constants used throughout the Pan AI Security MCP Relay system.
Constants are organized into logical groups for better maintainability and clarity.
"""

import sys
from datetime import datetime
from typing import Final

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from backports.strenum import StrEnum

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


class TransportType(StrEnum):
    """
    Enumeration of supported transport types for MCP communication.

    Attributes:
        STDIO: Standard input/output transport using subprocess pipes
        SSE: Server-Sent Events transport using HTTP streaming
    """

    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable_http"


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

SECURITY_ENV_KEYS = [
    "PANW_AI_SEC_API_KEY",
    "PANW_AI_SEC_API_ENDPOINT",
    "PANW_AI_PROFILE_NAME",
    "PANW_AI_PROFILE_ID",
]
"""
List of environment variable keys used for Security Scanner configuration.

Environment Variables:
    PANW_AI_SEC_API_KEY: Palo Alto Networks AI Runtime Security API authentication key
    PANW_AI_SEC_API_ENDPOINT: AI Runtime Security API endpoint URL (optional, uses default if not provided)
    PANW_AI_PROFILE_NAME: Name of the AI Runtime Security profile to use for scanning
    PANW_AI_PROFILE_ID: ID of the AI Runtime Security profile (alternative to profile name)

Note:
    Either PANW_AI_PROFILE_NAME or PANW_AI_PROFILE_ID must be provided.
    Configuration precedence: command line args > environment variables > .env file.
"""

EXPECTED_SECURITY_SCAN_RESULT_CONTENT_LENGTH: Final[int] = 1
"""Expected number of content items in security scan results."""

SECURITY_SCAN_RESPONSE_ACTION_BLOCK: Final[str] = "block"
"""Security scan response indicating content should be blocked."""

SECURITY_SCAN_RESPONSE_ACTION_ALLOW: Final[str] = "allow"
"""Security scan response indicating content is safe to proceed."""
