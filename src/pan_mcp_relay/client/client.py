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
Downstream MCP Client module.

Manages connections and communication with downstream MCP servers.
"""

import os
import string

from mcp import StdioServerParameters
from mcp.client.session_group import ServerParameters, SseServerParameters, StreamableHttpParameters
from pydantic import BaseModel, ConfigDict

from .. import utils
from ..configuration import HttpMcpServer, SseMcpServer, StdioMcpServer
from ..exceptions import McpRelayConfigurationError, McpRelayInternalError

log = utils.get_logger(__name__)


class RelayClient(BaseModel):
    """
    Manages MCP server connections and tool execution.

    Handles initialization, tool listing, and execution for a single
    downstream MCP server.
    """

    name: str
    config: StdioMcpServer | SseMcpServer | HttpMcpServer

    model_config = ConfigDict(arbitrary_types_allowed=False)

    def get_server_params(self) -> ServerParameters:
        match self.config:
            case StdioMcpServer():
                return self.get_stdio_parameters()
            case SseMcpServer() | HttpMcpServer():
                return self.get_http_parameters()

    def get_http_parameters(self) -> SseServerParameters | StreamableHttpParameters:
        """Generate MCP Server Parameters for HTTP-type clients (SSE, Streamable HTTP).

        All parameter values are subject to environment variable expansion.
        """
        url = self.config.url
        headers = self.config.headers
        if not url:
            err_msg = f"invalid MCP server configuration: {self.name} (missing url)"
            log.error(err_msg)
            raise McpRelayConfigurationError(err_msg)

        # Parse HTTP Header Values using Environment variables
        env = os.environ.copy()
        for k, v in headers.items():
            headers[k] = string.Template(v).safe_substitute(env)

        kwargs = dict(
            url=self.config.url,
            headers=headers,
            timeout=self.config.timeout,
            sse_read_timeout=self.config.sse_read_timeout,
        )
        if isinstance(self.config, HttpMcpServer):
            param_constructor = StreamableHttpParameters
            kwargs.update(dict(terminate_on_close=self.config.terminate_on_close))
        elif isinstance(self.config, SseMcpServer):
            param_constructor = SseServerParameters
        else:
            raise McpRelayInternalError(f"Invalid HTTP server type: {type(self.config)}")

        params = param_constructor(**kwargs)
        return params

    def get_stdio_parameters(self) -> StdioServerParameters:
        """Generate MCP Server Parameters for stdio clients.

        All parameter values are subject to environment variable expansion.
        """
        # Prepare environment variables
        env: dict[str, str] = os.environ.copy()
        if self.config.env:
            env.update(self.config["env"])
        command = self.config.command
        if not command:
            err_msg = f"invalid MCP server configuration: {self.name} (missing command)"
            log.error(err_msg)
            raise McpRelayConfigurationError(err_msg)
        config_env = self.config.env or {}
        # merge env + config_env, giving priority to config_env
        for k, v in config_env.items():
            if v is None:
                continue
            v = v.strip()
            if v:
                env[k] = string.Template(v).safe_substitute(os.environ)
        args = self.config.args
        for i, arg in enumerate(args):
            args[i] = string.Template(arg).safe_substitute(env)
        cwd = self.config.cwd
        if cwd:
            cwd = string.Template(str(cwd)).safe_substitute(env)
        log.info(f"Creating stdio client: '{command} {' '.join(args)}'")
        server_params = StdioServerParameters(command=command, args=args, env=env, cwd=cwd)
        return server_params
