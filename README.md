# Palo Alto Networks MCP Security Relay

A implementation of a security-enhanced Model Context Protocol (MCP) relay server that acts as an intermediary between clients and downstream MCP servers, providing security scanning and centralized orchestration capabilities.

<!--TOC-->
- [Palo Alto Networks MCP Security Relay](#palo-alto-networks-mcp-security-relay)
- [Overview](#overview)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Server Configuration](#server-configuration)
  - [Transport Options](#transport-options)
- [Usage](#usage)
  - [Running the Relay Server](#running-the-relay-server)
    - [Command Line Arguments](#command-line-arguments)
- [Error Handling \& Exceptions](#error-handling--exceptions)
- [Legal](#legal)

<!--TOC-->

<a id="overview" aria-hidden="true" href="#overview">

# Overview

</a>

The MCP Security Relay provides a security-enhanced intermediary layer for Model Context Protocol communications. It enables:

- **Security scanning** of tool requests and responses using integrated AI security services
- **Tool registry management** with deduplication, caching, and state management
- **Multi-server orchestration** supporting multiple downstream MCP servers
- **Hidden mode support** for bypassing security scans on trusted servers
- **Automatic tool discovery** and registration from configured downstream servers

<a id="installation" href="#installation">

# Installation

</a>

```sh

# Create and activate a virtual environment
python3 -m venv --prompt ${PWD##*/} .venv && source .venv/bin/activate

# Install required dependencies
python3 -m pip install -r requirements.txt
```

<a id="configuration" href="#configuration">

# Configuration

</a>

<a id="environment-variables" href="#environment-variables">

## Environment Variables

</a>

Create a `.env` file in the project root with the following variables:

```sh
# Required for Palo Alto Networks AI Security scanning
PANW_AI_PROFILE_NAME=YOUR_AI_PROFILE_NAME
PANW_AI_SEC_API_KEY=YOUR_API_KEY
PANW_AI_SEC_API_ENDPOINT=YOUR_API_ENDPOINT
PANW_AI_PROFILE_ID=YOUR_PROFILE_ID
```

<a id="server-configuration" href="#server-configuration">

## Server Configuration

</a>

Configure downstream MCP servers in `config/servers_config.json`:

**Note**: The `pan-aisecurity` server configuration is required and must be included in the servers configuration.

```json
{
  "mcpServers": {
    "pan-aisecurity": {
      "command": "python",
      "args": ["aisecurity/mcp_server/pan_security_server.py"],
      "env": {
        "hidden_mode": "enabled"
      }
    },
    "weather": {
      "command": "python",
      "args": ["other_mcp_tool_path/other_tool.py"]
    }
  }
}
```

<a id="transport-options" href="#transport-options">

## Transport Options

</a>

The relay supports two transport mechanisms:

- **STDIO Transport**: For local process communication (default)
- **SSE Transport**: For HTTP-based communication using Server-Sent Events

<a id="usage" href="#usage">

# Usage

</a>

<a id="running-the-relay-server" href="#running-the-relay-server">

## Running the Relay Server

</a>

```sh
# Run with STDIO transport (default)
python aisecurity/mcp_relay/pan_security_relay.py \
  --config-file=config/servers_config.json \
  --transport=stdio

# Run with SSE transport
python aisecurity/mcp_relay/pan_security_relay.py \
  --config-file=config/servers_config.json \
  --transport=sse \
  --host=127.0.0.1 \
  --port=8000
```

Additional configuration options:

```sh
python aisecurity/mcp_relay/pan_security_relay.py \
  --config-file=config/servers_config.json \
  --transport=stdio \
  --host=127.0.0.1 \
  --port=8000 \
  --TOOL_REGISTRY_CACHE_EXPIRY_IN_SECONDS=300 \
  --MAX_MCP_SERVERS=10 \
  --MAX_MCP_TOOLS=20
```

### Command Line Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--config-file` | ✅ | - | Path to the JSON configuration file containing MCP server definitions |
| `--transport` | ❌ | `stdio` | Transport protocol to use. Options: `stdio` (local process communication) or `sse` (HTTP Server-Sent Events) |
| `--host` | ❌ | `127.0.0.1` | Host address for SSE transport server (only used when `--transport=sse`) |
| `--port` | ❌ | `8000` | Port number for SSE transport server (only used when `--transport=sse`) |
| `--TOOL_REGISTRY_CACHE_EXPIRY_IN_SECONDS` | ❌ | `300` | Cache expiry time in seconds for the downstream MCP tool registry. Tools are re-scanned when cache expires |
| `--MAX_MCP_SERVERS` | ❌ | `32` | Maximum number of downstream MCP servers that can be configured. Prevents resource exhaustion |
| `--MAX_MCP_TOOLS` | ❌ | `64` | Maximum total number of MCP tools across all downstream servers. Enforces tool registry limits |



<a id="example-mcp-servers" href="#example-mcp-servers">


# Error Handling & Exceptions

</a>

The relay defines custom exceptions in `aisecurity/mcp_relay/exceptions.py`:

- **AISEC_MCP_RELAY_INTERNAL_ERROR**: Internal relay errors
- **AISEC_INVALID_CONFIGURATION**: Configuration validation errors
- **AISEC_TOOL_EXECUTION_ERROR**: Tool execution failures
- **AISEC_SECURITY_BLOCK**: Security scan blocked requests
- **AISEC_TOOL_NOT_FOUND**: Unknown tool requests
- **AISEC_SERVER_NOT_FOUND**: Unknown server requests
- **AISEC_VALIDATION_ERROR**: Input validation errors
- **AISEC_TOOL_REGISTRY_ERROR**: Tool registry operation errors

<a id="security-considerations" href="#security-considerations">

# Legal

Copyright (c) 2025, Palo Alto Networks
<!---Protected_by_PANW_Code_Armor_2024 - Y3ByfC9haWZ3L29wZW5zb3VyY2UvYWlzZWN1cml0eS1tY3AtcmVsYXl8MjE5NDV8bWFpbg== --->