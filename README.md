# Prisma AIRS MCP Security Relay

By Palo Alto Networks

<!--TOC-->

- [Prisma AIRS MCP Security Relay](#prisma-airs-mcp-security-relay)
- [Overview](#overview)
  - [Prerequisites](#prerequisites)
  - [Requirements for Prisma AIRS API Usage](#requirements-for-prisma-airs-api-usage)
- [Installation and Setup](#installation-and-setup)
  - [Install via pypi.org](#install-via-pypiorg)
  - [Install the bleeding edge development version](#install-the-bleeding-edge-development-version)
- [Configuration](#configuration)
  - [MCP Relay Server Configuration](#mcp-relay-server-configuration)
    - [Configuration Precedence](#configuration-precedence)
    - [Configuration File Format](#configuration-file-format)
  - [Environment Variables](#environment-variables)
  - [MCP Client Configuration](#mcp-client-configuration)
  - [Transport Options](#transport-options)
- [Usage](#usage)
  - [pan-mcp-relay CLI Usage](#pan-mcp-relay-cli-usage)
  - [Running the Relay Server](#running-the-relay-server)
    - [stdio transport (default)](#stdio-transport-default)
    - [SSE transport](#sse-transport)
- [Legal](#legal)

<!--TOC-->

<a id="overview" href="#overview">

# Overview

</a>

`pan-mcp-relay` is a security-enhanced [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) Relay (_Proxy_) Server providing real-time AI threat protection for MCP Clients, built with the [Prisma AIRS API].

`pan-mcp-relay` will help protect MCP Clients such as IDE's, LLM Chat Clients and AI Agents from harmful MCP Server Tools by automatically scanning and blocking
various threats, including prompt injections, malicious URLs, insecure outputs, AI agentic threats, sensitive data loss and more.

The MCP Relay scans all MCP Server tool descriptions, tool call parameters, and tool call responses.

For licensing, onboarding, activation, and to obtain an API authentication key and profile name, refer to the
[Prisma AIRS AI Runtime API Intecept] administration documentation.

## Prerequisites

1. Create and associate a [deployment profile](https://docs.paloaltonetworks.com/ai-runtime-security/activation-and-onboarding/ai-runtime-security-api-intercept-overview/ai-deployment-profile-airs-api-intercept) for Prisma AIRS AI Runtime API intercept in your Customer Support Portal.
2. [Onboard Prisma AIRS AI Runtime API intercept](https://docs.paloaltonetworks.com/ai-runtime-security/activation-and-onboarding/ai-runtime-security-api-intercept-overview/onboard-api-runtime-security-api-intercept-in-scm) in Strata Cloud Manager.
3. [Manage applications, API keys, security profiles, and custom topics](https://docs.paloaltonetworks.com/ai-runtime-security/administration/prevent-network-security-threats/airs-apirs-manage-api-keys-profile-apps) in Strata Cloud Manager.

## Requirements for Prisma AIRS API Usage

1. **API Key Token**: This token is generated during the onboarding process in Strata Cloud Manager (see the onboarding prerequisite step above).
Include the API key token in all API requests using the `x-pan-token` header.
2. **AI Security Profile Name**: This is the API security profile you created during the onboarding process in Strata Cloud Manager (see the prerequisite step on creating an API security profile above).
Specify this profile name or the profile ID in the API request payload in the `ai_profile` field.

> [!NOTE]
> You can manage API keys and AI security profiles in Strata Cloud Manager.
>
> 1. Log in to [Strata Cloud Manager](http://stratacloudmanager.paloaltonetworks.com/).
> 2. Navigate to **Insights > Prisma AIRS > Prisma AIRS AI Runtime: API Intercept**.
> 3. In the top right corner, click:
>
> - **Manage > API Keys** to copy, regenerate, or rotate the API key token.
> - **Manage > Security Profiles** to fetch details or update AI security profiles.
> - **Manage > Custom Topics** create or update custom topics for custom topic guardrails threat detections.
>
> For complete details, refer to adminstration guide for the section on how to [manage applications, API Keys, security profiles, and custom topics](https://docs.paloaltonetworks.com/ai-runtime-security/administration/prevent-network-security-threats/airs-apirs-manage-api-keys-profile-apps).

<a id="installation" href="#installation">

# Installation and Setup

</a>

We highly recommend using [uv](https://docs.astral.sh/uv/getting-started/installation/) over `pip` or `pipx`. Try it!

Update uv if already installed: `uv self update`

## Install via pypi.org

Install and run `pan-mcp-relay`, showing the CLI help:

```sh
uvx pan-mcp-relay --help

# or

uv tool install pan-mcp-relay
pan-mcp-relay --help
```

## Install the bleeding edge development version

```sh
uv tool install https://github.com/PaloAltoNetworks/aisecurity-mcp-relay.git
pan-mcp-relay --help
```

Create an [`mcp-relay.yaml`](#configuration) configuration file containing:
1. Prisma AIRS API Configuration
   * Prisma AIRS API Key
   * Prisma AIRS AI Profile
   * Prisma AIRS API Endpoint (Optional)
2. MCP Servers
   * Supports stdio, SSE and HTTP MCP Servers.
3. Run the MCP Relay Server


<a id="configuration" href="#configuration">

# Configuration

</a>

<a id="relay-configuration" href="#relay-configuration">

## MCP Relay Server Configuration

</a>


### Configuration Precedence

1. CLI Flags
2. Environment Variables
3. .env file variables
4. Configuration File

`pan-mcp-relay` supports loading a configuration file via `--config-file` flag, `MCP_RELAY_CONFIG_FILE` environment variable, or detecting a configuration file on a set of pre-determined locations:

- `--config-file` (`-c`) CLI flag
- `MCP_RELAY_CONFIG_FILE` environment variable
- `./mcp-relay.yaml`
- `~/.mcp-relay.yaml`
- `~/.config/pan-mcp-relay/mcp-relay.yaml`
- `./mcp-relay.json`
- `~/.mcp-relay.json`
- `~/.config/pan-mcp-relay/mcp-relay.json`

### Configuration File Format

An example MCP Relay Server configuration is available in the repository in `examples/config/mcp-relay.yaml`

Copy or create a new `mcp-relay.yaml` file. The only _required_ section is `mcpServers: {}`.

```yaml
# mcpRelay section is optional.
# API Key, AI Profile and API Endpoint can be specified via CLI flags or environment variables.
mcpRelay:
  # Prisma AIRS API Key (required), environment variables supported
  apiKey: |
    ${PRISMA_AIRS_API_KEY}
  # Prisma AIRS AI Profile Name or ID (required), environment variables supported
  aiProfile: |
    your-ai-profile-name-or-id
  # Endpoint Optional, default shown
  # endpoint: |
  #  https://service.api.aisecurity.paloaltonetworks.com

# mcpServers section is required, with at least one MCP Server.
mcpServers:
  # Example / demo MCP Servers
  homebrew:
    command: brew
    args:
      - mcp-server
    # Optional working directory, supports environment variables
    cwd: "${HOMEBREW_PREFIX}"
    # optional environment variables, inherited from the parent shell
    env:
      HOMEBREW_NO_ENV_HINTS: 1
  fetch:
    command: uvx
    args:
      - mcp-server-fetch

  # filesystem:
  #   command: npx
  #   args:
  #     - -y
  #     - '@modelcontextprotocol/server-filesystem'
  #     - /var/tmp/change/this/path
  #     # Command line arguments support environment variables
  #     - "${XDG_PICTURES_DIR}"
```

<a id="environment-variables" href="#environment-variables">

## Environment Variables

</a>

In addition to CLI flags and the configuration file, `pan-mcp-relay` supports reading configuration through the following environment variables:

```sh
# Required for Prisma AIRS API
PRISMA_AIRS_API_KEY=YOUR_API_KEY
# Required for Prisma AIRS API
PRISMA_AIRS_AI_PROFILE=YOUR_AI_PROFILE_NAME

# Optional, default is https://service.api.aisecurity.paloaltonetworks.com
PRISMA_AIRS_API_ENDPOINT=YOUR_API_ENDPOINT
# See https://pan.dev/prisma-airs/scan/api/#scan-api-endpoints for additional regional API endpoints

# Defaults shown for all other Environment Variables
MCP_RELAY_CONFIG_FILE=~/.config/pan-mcp-relay/mcp-relay.yaml
MCP_RELAY_TRANSPORT=stdio
# Host For SSE Transport Mode
MCP_RELAY_HOST=127.0.0.1
# Port for SSE Transport Mode
MCP_RELAY_TOOL_CACHE_TTL=86400
MCP_RELAY_MAX_SERVERS=32
MCP_RELAY_MAX_TOOLS=64
# Path to optional .env file
MCP_RELAY_DOTENV=
# Supports $PATH-style colon-separated list and environment variables. Directory entries will search for a file named `.env`
# MCP_RELAY_DOTENV=$HOME/.env:~/.config/pan-mcp-relay:$PWD
```

<a id="client-configuration" href="#client-configuration">

## MCP Client Configuration

</a>

Create a new config file `mcp-relay.json` to use with your MCP Client (IDE, Chat Client, or Agent).

```json
{
  "mcpServers": {
    "pan-mcp-relay": {
      "command": "uvx",
      "args": [
        "pan-mcp-relay"
      ]
    }
  }
}
```

> [!CAUTION]
>
> `pan-mcp-relay` should be the only MCP Server listed in your MCP Client configuration file.
>
> Any other MCP Servers listed here will **NOT** be visible to the security capabilities of the MCP Relay.

Optionally, specify additional environment variables or CLI flags:


```json
{
  "mcpServers": {
    "pan-mcp-relay": {
      "command": "uvx",
      "args": [
        "pan-mcp-relay",
        "--config-file",
        "~/.config/pan-mcp-relay/mcp-relay.yaml"
      ],
      "env": {
        "PRISMA_AIRS_AI_PROFILE": "your-ai-profile",
        "MCP_RELAY_LOG_LEVEL": "WARNING"
      }
    }
  }
}
```


<a id="transport-options" href="#transport-options">

## Transport Options

</a>

The relay supports two transport mechanisms:

- **`stdio` Transport**: For local process communication (default)
- **`SSE` Transport**: For HTTP-based communication using Server-Sent Events

> [!NOTE]
> Running the MCP Server in Streamable HTTP is coming soon.

<a id="usage" href="#usage">

# Usage

</a>

<a id="pan-mcp-relay-cli-usage" href="#pan-mcp-relay-cli-usage">

## pan-mcp-relay CLI Usage

</a>

```terminaloutput
uv run pan-mcp-relay --help
Usage: pan-mcp-relay [OPTIONS] COMMAND [ARGS]...

  Run the MCP Relay Server.

Options:
  -k, --api-key TEXT              Prisma AIRS API Key [PRISMA_AIRS_API_KEY=]
  -e, --api-endpoint TEXT         Prisma AIRS API Endpoint [PRISMA_AIRS_API_ENDPOINT=]
  -p, --ai-profile TEXT           Prisma AIRS AI Profile Name or ID [PRISMA_AIRS_AI_PROFILE=]
  -c, --config-file FILE          Path to configuration file (yaml, json) [MCP_RELAY_CONFIG_FILE=]
  -t, --transport [stdio|sse]     Transport protocol to use [MCP_RELAY_TRANSPORT=]  [default: stdio]
  -h, --host TEXT                 Host for HTTP/SSE server [MCP_RELAY_HOST=]  [default: 127.0.0.1]
  -p, --port INTEGER              Port for HTTP/SSE server [MCP_RELAY_PORT=]  [default: 8000]
  -t, --tool-registry-cache-ttl INTEGER
                                  Tool registry cache TTL (in seconds) [MCP_RELAY_TOOL_CACHE_TTL=]  [default: 86400]
  -m, --max-mcp-servers INTEGER   Maximum number of downstream MCP servers to allow [MCP_RELAY_MAX_SERVERS=]  [default: 32]
  -n, --max-mcp-tools INTEGER     Maximum number of MCP tools to allow [MCP_RELAY_MAX_TOOLS=]  [default: 64]
  --env TEXT                      Use ./.env file, or specify colon separated path to .env file(s)or directories containing .env files. [MCP_RELAY_DOTENV=]
  --system-ca                     Use System CA instead of Mozilla CA Bundle
  --capath FILE                   Path to Custom Trusted CA bundle
  -d, --debug                     Extremely verbose logging output (DEBUG)
  -v, --verbose                   Verbose logging output (INFO, DEFAULT)
  -q, --quiet                     Minimal logging output (WARNING)
  --show-config, --dump-config    Show configuration and exit [MCP_RELAY_SHOW_CONFIG=]
  -V, --version                   Show the version and exit.
  --help                          Show this message and exit.

Commands:
  json-schema  Print Configuration File JSON Schema, optionally to a file.
  run          Run the MCP Relay Server.
  show-config  Print MCP Relay Configuration and exit.
```

<a id="running-the-relay-server" href="#running-the-relay-server">

## Running the Relay Server

</a>

<a id="stdio-transport-default" href="#stdio-transport-default">

### stdio transport (default)

</a>

```sh
# Run with stdio transport with automatic configuration detection (default)
uvx pan-mcp-relay

# Specify a configuration file
uvx pan-mcp-relay --config-file ~/.config/pan-mcp-relay/mcp-relay.yaml

# Specify a path to a custom .env file
uvx pan-mcp-relay --env /var/run/secrets/.env
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


[Prisma AIRS API]: https://pan.dev/prisma-airs/scan/api/
[Prisma AIRS AI Runtime API Intecept]: https://docs.paloaltonetworks.com/ai-runtime-security/activation-and-onboarding/ai-runtime-security-api-intercept-overview
