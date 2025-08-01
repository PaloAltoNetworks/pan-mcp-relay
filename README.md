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
- [Examples](#examples)
  - [Stdio Client Example](#stdio-client-example)
  - [SSE Client Example Configuration](#sse-client-example-configuration)
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
      "args": ["path/to/pan_security_server.py"],
      "env": {
        "hidden_mode": "enabled"
      }
    },
    "example-server": {
      "command": "node",
      "args": ["path/to/server/index.js"]
    },
    "another-server": {
      "command": "python",
      "args": ["path/to/another/server.py"]
    },
      "other-server-SSE-mode": {
      "type": "sse",
      "baseUrl": "url_of_other-SSE-server"
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
python -m pan_aisecurity_mcp.mcp_relay.pan_security_relay \
  --config-file=config/servers_config.json \
  --transport=stdio

# Run with SSE transport
python -m pan_aisecurity_mcp.mcp_relay.pan_security_relay \
  --config-file=config/servers_config.json \
  --transport=sse \
  --host=127.0.0.1 \
  --port=8000
```

Additional configuration options:

```sh
python -m pan_aisecurity_mcp.mcp_relay.pan_security_relay \
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




<a id="examples" href="#examples">

# Examples

</a>

<a id="stdio-client-example" href="#stdio-client-example">

## Stdio Client Example

</a>

This example demonstrates how to run the interactive client to communicate with the relay server using `stdio`.

**1. Run the Interactive Client:**

Run the `pan_security_relay_stdio_client.py` script. This script connects to the running relay and provides an interactive command prompt.

```sh
python examples/pan_security_relay_stdio_client.py \
  --relay-module=pan_aisecurity_mcp.mcp_relay.pan_security_relay \
  --config-file=config/servers_config_example.json
```

**2. Interact with the Client:**

Once the client starts, you can use the following commands to interact with the downstream MCP servers through the relay:

*   **`list`**: Displays all available tools from the downstream servers.
*   **`call <tool_name> [json_arguments]`**: Executes a specific tool with the provided arguments. For example, `call list_downstream_servers_info`.
*   **`servers`**: Shows a list of all configured downstream servers and their tools.
*   **`quit`**: Exits the interactive client.

Using these commands, you can test and debug the MCP relay and its connected downstream servers.

<a id="sse-client-configuration" href="#sse-client-configuration">

## SSE Client Example Configuration

</a>

To connect a client to the relay server when it's running in SSE mode, you need to first start the relay server with the transport set to `sse`.

**1. Start the Relay Server in SSE Mode:**

```sh
python -m pan_aisecurity_mcp.mcp_relay.pan_security_relay \
  --config-file=config/servers_config.json \
  --transport=sse \
  --host=127.0.0.1 \
  --port=8000
```

**2. Configure Your Client:**

Then, in your client's configuration (for example, in a `config.json` or a similar file), add the following to connect to the SSE endpoint of the relay:
```json
{
  "mcpServers": {
    "pan_security_relay_SSE": {
      "type": "sse",
      "baseUrl": "http://127.0.0.1:8000/sse"
    }
  }
}
```

This configuration tells your client how to find and communicate with the MCP Security Relay using the SSE protocol.

# Error Handling & Exceptions

</a>

The relay defines custom exceptions in `pan_aisecurity_mcp/mcp_relay/exceptions.py`:

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