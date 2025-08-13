# Palo Alto Networks MCP Security Relay

A security-enhanced [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) relay server that acts as an intermediary between clients and downstream
MCP servers, providing security scanning and centralized orchestration capabilities.

<!--TOC-->

- [Palo Alto Networks MCP Security Relay](#palo-alto-networks-mcp-security-relay)
- [Overview](#overview)
- [Installation and Setup](#installation-and-setup)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Relay Server Configuration](#relay-server-configuration)
  - [MCP Server Configuration](#mcp-server-configuration)
  - [Transport Options](#transport-options)
- [Usage](#usage)
  - [pan-mcp-relay CLI Usage](#pan-mcp-relay-cli-usage)
  - [Running the Relay Server](#running-the-relay-server)
    - [stdio transport (default)](#stdio-transport-default)
    - [SSE transport](#sse-transport)
    - [Command Line Arguments](#command-line-arguments)
- [Examples](#examples)
  - [Stdio Client Example](#stdio-client-example)
  - [SSE Client Example Configuration](#sse-client-example-configuration)
- [Legal](#legal)

<!--TOC-->

<a id="overview" href="#overview">

# Overview

</a>

The MCP Security Relay provides a security-enhanced intermediary layer for Model Context Protocol communications

- **Security scanning** of tool requests and responses using integrated AI security services
- **Tool registry management** with deduplication, caching, and state management
- **Multiserver orchestration** supporting multiple downstream MCP servers
- **Hidden mode support** for bypassing security scans on trusted servers
- **Automatic tool discovery** and registration from configured downstream servers

<a id="installation" href="#installation">

# Installation and Setup

</a>

This project uses [uv](https://docs.astral.sh/uv/getting-started/installation/).

1. Install or Update [uv https://docs.astral.sh/uv/getting-started/installation/](https://docs.astral.sh/uv/getting-started/installation/)
  1. Update uv if already installed: `uv self update`
2. Clone this repository.
2. Install the project dependencies using `uv sync`
3. Create the MCP Relay Configuration File
4. Run the MCP Relay Server

```sh
git clone https://github.com/paloaltonetworks/aisecurity-mcp-relay.git

cd aisecurity-mcp-relay

uv sync

# .local/ directory is git-ignored, you may use it for your custom configuration
cp examples/config/config-example.json .local/config.json
```

<a id="configuration" href="#configuration">

# Configuration

</a>

<a id="environment-variables" href="#environment-variables">

## Environment Variables

</a>

Create a `.env` file in the git repo root with the following variables:

```sh
# Required for Palo Alto Networks AI Security scanning
PANW_AI_PROFILE_NAME=YOUR_AI_PROFILE_NAME
PANW_AI_SEC_API_KEY=YOUR_API_KEY
PANW_AI_SEC_API_ENDPOINT=YOUR_API_ENDPOINT
```


<a id="server-configuration" href="#server-configuration">

## Relay Server Configuration

</a>

Create a new config file `mcp-relay.json` to use with your IDE, Chat Client, or MCP System.

```json
{
  "mcpServers": {
    "pan-mcp-relay": {
      "command": "uvx",
      "args": [
        "pan-mcp-relay",
        "--config",
        "pan-mcp-relay-config.json"
      ],
      "env": {
        "PRISMA_AIRS_API_KEY": "YOUR_PRISMA_AIRS_API_KEY"
      },
      "cwd": "$HOME/optional/working/directory"
    }
  }
}
```

<a id="server-configuration" href="#server-configuration">

## MCP Server Configuration

</a>


Copy or create a new `mcp-servers.json` file. Configure downstream MCP servers in `mcp-servers.json`:

```json
{
  "mcpServers": {
    "example-server": {
      "command": "node",
      "args": ["path/to/server/index.js"]
    },
    "another-server": {
      "command": "python",
      "args": ["path/to/another/server.py"]
    }
  }
}
```

**Note:**

* MCP Relay only supports local MCP servers currently.

<!--
TODO: Add Environment and CWD support to MCP Server Config
TODO: Support Remote MCP Servers
-->

<a id="transport-options" href="#transport-options">

## Transport Options

</a>

The relay supports two transport mechanisms:

- **STDIO Transport**: For local process communication (default)
- **SSE Transport**: For HTTP-based communication using Server-Sent Events

<a id="usage" href="#usage">

# Usage

</a>

<a id="pan-mcp-relay-cli-usage" href="#pan-mcp-relay-cli-usage">

## pan-mcp-relay CLI Usage

</a>

```sh
usage: pan-mcp-relay [-h] --config-file CONFIG_FILE [--transport {stdio,sse}] [--host HOST] [--port PORT]
                     [--tool-registry-cache-expiry-in-seconds TOOL_REGISTRY_CACHE_EXPIRY_IN_SECONDS] 
                     [--max-mcp-servers MAX_MCP_SERVERS] [--max-mcp-tools MAX_MCP_TOOLS]
                     [--PANW_AI_SEC_API_KEY PANW_AI_SEC_API_KEY] [--PANW_AI_SEC_API_ENDPOINT PANW_AI_SEC_API_ENDPOINT]
                     [--PANW_AI_PROFILE_NAME PANW_AI_PROFILE_NAME] [--PANW_AI_PROFILE_ID PANW_AI_PROFILE_ID]

options:
  -h, --help            show this help message and exit
  --config-file CONFIG_FILE
                        Path to config file
  --transport {stdio,sse}
                        Transport protocol to use
  --host HOST           Host for SSE server
  --port PORT           Port for SSE server
  --tool-registry-cache-expiry-in-seconds TOOL_REGISTRY_CACHE_EXPIRY_IN_SECONDS
                        Downsteam mcp tool registry cache expiry
  --max-mcp-servers MAX_MCP_SERVERS
                        Max number of downstream servers
  --max-mcp-tools MAX_MCP_TOOLS
                        Max number of MCP tools
  --PANW_AI_SEC_API_KEY PANW_AI_SEC_API_KEY
                        PANW AI Security API Key
  --PANW_AI_SEC_API_ENDPOINT PANW_AI_SEC_API_ENDPOINT
                        PANW AI Security API Endpoint
  --PANW_AI_PROFILE_NAME PANW_AI_PROFILE_NAME
                        PANW AI Profile Name
  --PANW_AI_PROFILE_ID PANW_AI_PROFILE_ID
                        PANW AI Profile ID
```

<a id="running-the-relay-server" href="#running-the-relay-server">

## Running the Relay Server

</a>

<a id="stdio-transport-default" href="#stdio-transport-default">

### stdio transport (default)

</a>

```sh
# Run with STDIO transport (default)
uv run pan-mcp-relay \
  --config-file=config.json
```
<a id="stdio-transport-security" href="#stdio-transport-security">

### stdio transport with security configuration

</a>

```sh
# Run with STDIO transport and security scanning enabled
uv run pan-mcp-relay \
  --config-file=config.json \
  --PANW_AI_PROFILE_NAME=default-profile-name \
  --PANW_AI_SEC_API_KEY=your-api-key \
  --PANW_AI_SEC_API_ENDPOINT=https://service.api.aisecurity.paloaltonetworks.com \
  --PANW_AI_PROFILE_ID=default-profile-id

# Alternative: Using environment variables (recommended for sensitive information)
export PANW_AI_SEC_API_KEY=your-api-key
export PANW_AI_SEC_API_ENDPOINT=https://service.api.aisecurity.paloaltonetworks.com
export PANW_AI_PROFILE_NAME=default-profile-name
export PANW_AI_PROFILE_ID=default-profile-id
uv run pan-mcp-relay --config-file=config.json
```
<a id="sse-transport" href="#sse-transport">

### SSE transport

</a>

```sh
# Run with SSE transport
uv run pan-mcp-relay \
  --config-file=config.json \
  --transport=sse \
  --host=127.0.0.1 \
  --port=8000
```

### Command Line Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--config-file` | ✅ | - | Path to the JSON configuration file containing MCP server definitions |
| `--transport` | ❌ | `stdio` | Transport protocol to use. Options: `stdio` (local process communication) or `sse` (HTTP Server-Sent Events) |
| `--host` | ❌ | `127.0.0.1` | Host address for SSE transport server (only used when `--transport=sse`) |
| `--port` | ❌ | `8000` | Port number for SSE transport server (only used when `--transport=sse`) |
| `--tool-registry-cache-expiry-in-seconds` | ❌ | `300` | Cache expiry time in seconds for the downstream MCP tool registry. Tools are re-scanned when cache expires |
| `--max-mcp-servers` | ❌ | `32` | Maximum number of downstream MCP servers that can be configured. Prevents resource exhaustion |
| `--max-mcp-tools` | ❌ | `64` | Maximum total number of MCP tools across all downstream servers. Enforces tool registry limits |
| `--PANW_AI_SEC_API_KEY` | ❌ | - | Palo Alto Networks AI Security API authentication key. Can also be set via environment variable |
| `--PANW_AI_SEC_API_ENDPOINT` | ❌ | - | AI Security API endpoint URL. Uses default endpoint if not provided. Can also be set via environment variable |
| `--PANW_AI_PROFILE_NAME` | ❌* | - | Name of the AI security profile to use for scanning. Either this or `--PANW_AI_PROFILE_ID` is required |
| `--PANW_AI_PROFILE_ID` | ❌* | - | ID of the AI security profile to use for scanning. Either this or `--PANW_AI_PROFILE_NAME` is required |

**Note:** Arguments marked with * indicate that at least one of the profile options (name or ID) must be provided either via command line or environment variables.

**Configuration Priority:** Command line arguments take precedence over environment variables, which take precedence over `.env` file values.

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
python examples/clients/stdio/pan_security_relay_stdio_client.py \
  --relay-module=pan_aisecurity_mcp_relay.main \
  --config-file=config.json
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
uv run pan-mcp-relay \
  --config-file=config/config-example.json \
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

<a id="legal" href="#legal">

# Legal

</a>

Copyright (c) 2025, Palo Alto Networks

Licensed under the [Polyform Internal Use License 1.0.0](https://polyformproject.org/licenses/internal-use/1.0.0)
(the "License"); you may not use this file except in compliance with the License.

You may obtain a copy of the License at:

https://polyformproject.org/licenses/internal-use/1.0.0

(or)

https://github.com/polyformproject/polyform-licenses/blob/76a278c4/PolyForm-Internal-Use-1.0.0.md

As far as the law allows, the software comes as is, without any warranty
or condition, and the licensor will not be liable to you for any damages
arising out of these terms or the use or nature of the software, under
any kind of legal claim.
<!---Protected_by_PANW_Code_Armor_2024 - Y3ByfC9haWZ3L29wZW5zb3VyY2UvYWlzZWN1cml0eS1tY3AtcmVsYXl8MjE5NDV8bWFpbg== --->
