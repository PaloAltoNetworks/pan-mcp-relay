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

import re
from datetime import datetime
from enum import StrEnum
from typing import Final

API_DOMAIN = "api.aisecurity.paloaltonetworks.com"
API_ENDPOINT_RE = r"^https://service(?:-[a-z]{2}|\.[a-z]{2,3})?\." + re.escape(API_DOMAIN) + r"/?$"
DEFAULT_API_ENDPOINT = f"https://service.{API_DOMAIN}"

ENV_VAR_RE = re.compile(r"[^\n]*(\${\w+}|\$\w+)")

# Environment Variables

API_PREFIX = "PRISMA_AIRS"
RELAY_PREFIX = "MCP_RELAY"

ENV_API_KEY = f"{API_PREFIX}_API_KEY"
"""Prisma AIRS API authentication key"""

ENV_API_ENDPOINT = f"{API_PREFIX}_API_ENDPOINT"
"""Prisma AIRS API endpoint URL (optional, uses default if not provided)"""

ENV_AI_PROFILE = f"{API_PREFIX}_AI_PROFILE"
""" Name or ID of the AI Runtime Security profile to use for scanning"""

ENV_CONFIG_FILE = f"{RELAY_PREFIX}_CONFIG_FILE"
"""Path to configuration file"""

ENV_HOST = f"{RELAY_PREFIX}_HOST"
ENV_PORT = f"{RELAY_PREFIX}_PORT"
ENV_DOTENV = f"{RELAY_PREFIX}_DOTENV"
ENV_SHOW_CONFIG = f"{RELAY_PREFIX}_SHOW_CONFIG"
ENV_TRANSPORT = f"{RELAY_PREFIX}_TRANSPORT"
ENV_TOOL_CACHE_TTL = f"{RELAY_PREFIX}_TOOL_CACHE_TTL"
ENV_MAX_SERVERS = f"{RELAY_PREFIX}_MAX_SERVERS"
ENV_MAX_TOOLS = f"{RELAY_PREFIX}_MAX_TOOLS"
ENV_LOG_LEVEL = f"{RELAY_PREFIX}_LOG_LEVEL"

f"""
List of environment variable keys used for Security Scanner configuration.

Environment Variables:
    {ENV_API_KEY}: {ENV_API_KEY.__doc__}
    {ENV_API_ENDPOINT}: {ENV_API_ENDPOINT.__doc__}
    {ENV_AI_PROFILE}: {ENV_AI_PROFILE.__doc__}

Note:
    Configuration precedence: CLI Flags > Environment > .env file.
"""


# =============================================================================
# SERVER IDENTIFICATION
# =============================================================================

MCP_RELAY_NAME: Final[str] = "pan-mcp-relay"
"""Name identifier for the MCP relay server component."""


# =============================================================================
# TRANSPORT TYPES
# =============================================================================


class TransportType(StrEnum):
    """
    Enumeration of supported transport types for MCP communication.

    Attributes:
        stdio: Standard input/output transport using subprocess pipes
        sse: Server-Sent Events transport using HTTP streaming
        http: HTTP transport using the Streamable HTTP protocol
    """

    stdio = "stdio"
    sse = "sse"
    http = "http"

    def __repr__(self) -> str:
        return str(self.value)

    def __str__(self) -> str:
        return str(self.value)


# =============================================================================
# DEFAULT VALUES AND LIMITS
# =============================================================================

TOOL_REGISTRY_CACHE_TTL_DEFAULT: Final[int] = 60 * 60 * 24
"""Default cache expiry time for tool registry in seconds (24 hours)."""

MAX_MCP_SERVERS_DEFAULT: Final[int] = 32
"""Maximum number of downstream servers that can be configured."""

MAX_MCP_TOOLS_DEFAULT: Final[int] = 256
"""Maximum total number of tools across all servers."""


# =============================================================================
# TIME CONSTANTS
# =============================================================================

UNIX_EPOCH: Final[datetime] = datetime.fromtimestamp(0)
"""Unix epoch reference time (1970-01-01 00:00:00 UTC)."""


# =============================================================================
# TOOL NAMES
# =============================================================================

TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO: Final[str] = f"{MCP_RELAY_NAME}:list_downstream_servers_info"
"""Tool name for listing downstream server information."""


# =============================================================================
# SECURITY SCAN CONSTANTS
# =============================================================================

EXPECTED_SECURITY_SCAN_RESULT_CONTENT_LENGTH: Final[int] = 1
"""Expected number of content items in security scan results."""

SYNC_SCAN_PATH = "/v1/scan/sync/request"
