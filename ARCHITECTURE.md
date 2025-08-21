
# Technical Architecture

## 1. Overview

The MCP Security Relay is a Python-based application that acts as a secure intermediary between clients and downstream Model Context Protocol (MCP) servers. Its primary purpose is to enhance security by scanning all tool descriptions, requests, and responses for potential threats, while also providing centralized orchestration and management of multiple downstream MCP servers.

### 1.1. Purpose and Use Cases

The key goals of the MCP Security Relay are:

- **Security Enchancement**: To provide a layer of security by scanning all communications between clients and MCP servers. This helps in preventing prompt injection, data leakage, and other security threats.
- **Centralized Orchestration**: To manage and interact with multiple downstream MCP servers from a single point of entry. This simplifies the client-side configuration and logic.
- **Tool Management**: To provide a unified and deduplicated registry of tools available from all downstream servers.

**Example Use Cases:**

- **Secure AI Agent**: An AI agent that uses various tools (e.g., file system access, code execution) can be configured to communicate with the MCP Security Relay. The relay will scan all tool function call requests and responses, ensuring all MCP Tool interactions are scanned for security risks.
- **Multi-Server Environment**: In a scenario with multiple specialized MCP servers (e.g., one for database access, another for web scraping), the relay can provide a single, unified interface to all of them, while enforcing security policies across the board.

## 2. Technical Walkthrough

### 2.1. Project Structure

The project is structured as a standard Python application:

- **`src/pan_mcp_relay/`**: Contains the core source code of the application.
    - **`main.py`**: The main entry point of the application. It handles command-line argument parsing and initializes the relay server.
    - **`pan_security_relay.py`**: The core of the relay server. It manages downstream servers, the tool registry, and security scanning.
    - **`downstream_mcp_client.py`**: A client for communicating with downstream MCP servers.
    - **`security_scanner.py`**: Handles the security scanning of requests and responses.
    - **`tool_registry.py`**: Manages the collection of tools from all downstream servers.
    - **`tool.py`**: Defines the data models for tools.
    - **`configuration.py`**: Manages the loading of configuration from files and environment variables.
    - **`constants.py`**: Defines constants used throughout the application.
    - **`exceptions.py`**: Defines custom exception classes.
    - **`mcp_server/`**: Contains the implementation of the MCP server that provides the security scanning functionality.
- **`tests/`**: Contains unit and integration tests.
- **`examples/`**: Contains example configurations and clients.
- **`pyproject.toml`**: Defines Python project metadata, packaging information, and dependencies.

### 2.2. Execution Logic and Data Flow

1.  **Initialization**:
    - A user invokes the command `uvx pan-mcp-relay` to download, install, and execute the application.
    - The application is started via the `pan-mcp-relay` [package entrypoint] script, which calls the `entrypoint` function in `main.py`.
    - The `main` function parses command-line arguments, including the path to the configuration file.
    - An instance of `PanSecurityRelay` is created.
    - The `initialize` method of `PanSecurityRelay` is called. This method:
        - Loads the configuration from the specified JSON file.
        - Initializes the `SecurityScanner`. This involves starting a dedicated `pan-aisecurity` MCP server as a subprocess.
        - Updates the `ToolRegistry` by connecting to each configured downstream MCP server, listing its tools, and scanning them for security risks.

2.  **Client Interaction**:
    - The relay server is invoked with either `stdio` or Streamable HTTP transports.
    - A client connects to the relay server.
    - The client requests the list of available tools by sending a `list_tools` request.
    - The `PanSecurityRelay` handles this request by consulting its `ToolRegistry` and returning a list of all enabled tools.

3.  **Tool Execution**:
    - The client requests to execute a tool by sending a `call_tool` request with the tool name and arguments.
    - The `PanSecurityRelay` receives the request and performs the following steps:
        1.  **Request Scanning**: The `SecurityScanner` scans the tool name and arguments for any security threats. If a threat is detected, the request is blocked, and an error is returned to the client.
        2.  **Tool Lookup**: The `ToolRegistry` is queried to find the server that provides the requested tool.
        3.  **Downstream Execution**: A `DownstreamMcpClient` is used to connect to the appropriate downstream server and execute the tool.
        4.  **Response Scanning**: The response from the downstream server is scanned by the `SecurityScanner`. If the response contains sensitive information or other threats, it is blocked, and an error is returned to the client.
        5.  **Return Result**: If both the request and response are deemed safe, the result is returned to the client.

### 2.3. Configuration

The relay server is configured via a JSON file. The main sections of the configuration are:

- **`mcpServers`**: A dictionary where each key is a server name and the value is an object describing how to run the server (e.g., the command and arguments to start the server process).
- **`hidden_mode`**: A boolean flag that, if set to `true` for a server, will bypass security scanning for that server's tools.

Environment variables are used to configure the Palo Alto Networks AI Security API credentials (`PANW_AI_SEC_API_KEY`, etc.).

### 2.4. Error Handling

The application uses a set of custom exception classes defined in `exceptions.py`. These exceptions are used to handle various error conditions, such as:

- **`InvalidConfiguration`**: If the configuration file is invalid.
- **`ToolExecutionError`**: If an error occurs while executing a tool on a downstream server.
- **`SecurityBlock`**: If a request or response is blocked by the security scanner.
- **`ToolNotFound`**: If the requested tool is not found in the registry.

When an exception is caught, it is logged, and a structured error message is sent back to the client in the MCP format.


[package entrypoint]: https://packaging.python.org/en/latest/specifications/pyproject-toml/#entry-points
