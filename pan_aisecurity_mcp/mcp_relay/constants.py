"""
Constants for MCP Relay application.
"""

from datetime import datetime


# Server Names
SECURITY_SERVER_NAME = "pan-aisecurity"
MCP_RELAY_NAME = "pan-aisecurity-relay"

# Configuration Labels
ENVIRONMENT_CONFIG_LABEL = "env"
MCP_SERVER_CONFIG_LABEL = "mcpServers"
HIDDEN_MODE_LABEL = "hidden_mode"
HIDDEN_MODE_ENABLED = "enabled"
MCP_RELAY_TRANSPORT_SSE = "sse"
MCP_RELAY_TRANSPORT_STDIO = "stdio"

# Default Values
TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT = 300
MAX_DOWNSTREAM_SERVERS_DEFAULT = 32
MAX_DOWNSTREAM_TOOLS_DEFAULT = 64

# Time Constants
UNIX_EPOCH = datetime.fromtimestamp(0)

# Tool Names
TOOL_NAME_LIST_DOWNSTREAM_SERVERS_INFO = "list_downstream_servers_info"
TOOL_NAME_PAN_AISECURITY_INLINE_SCAN = "pan_inline_scan"

# Security Scan Tool Constants
EXPECTED_SECURITY_SCAN_RESULT_CONTENT_LENGTH = 1
SECURITY_SCAN_RESPONSE_ACTION_BLOCK = "block"
SECURITY_SCAN_RESPONSE_ACTION_ALLOW = "allow"
