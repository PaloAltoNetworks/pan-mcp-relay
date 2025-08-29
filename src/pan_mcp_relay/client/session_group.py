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

import contextlib
from typing import Any

import mcp.client.session_group
import tenacity
from mcp import McpError, types
from mcp.client.session_group import ServerParameters
from pydantic import validate_call
from tenacity import retry_if_not_exception_type, stop_after_attempt

from .. import utils

log = utils.get_logger(__name__)


def serverinfo_str(serverinfo: types.Implementation) -> str:
    fields: list[str] = []
    if serverinfo.name:
        fields.append(serverinfo.name)
    if serverinfo.title:
        fields.append(serverinfo.title)
    if serverinfo.version:
        fields.append(serverinfo.version)
    return ":".join(fields)


class RelaySessionGroup(mcp.client.session_group.ClientSessionGroup):
    _session_to_server_name: dict[mcp.ClientSession, str]
    """Lookup Server Name by mcp.ClientSession"""
    _tool_to_serverinfo: dict[str, types.Implementation]
    """Lookup Server info by Tool Name"""

    def __init__(
        self,
        exit_stack: contextlib.AsyncExitStack | None = None,
    ) -> None:
        super().__init__(exit_stack, component_name_hook=self.component_name_hook)
        self._server_info_to_server_name = {}
        self._session_to_server_name = {}
        self._tool_to_serverinfo = {}

    @tenacity.retry(retry=(retry_if_not_exception_type(McpError)), stop=stop_after_attempt(3))
    async def call_tool(self, name: str, args: dict[str, Any]) -> types.CallToolResult:
        server_name = await self.get_server_name_by_tool(name)
        log_msg = f"call_tool: name={name} args={args}"
        if server_name:
            log_msg = f"[{server_name}] {log_msg}"
        log.debug(log_msg)
        return await super().call_tool(name, args)

    @validate_call
    async def get_server_name_by_tool(self, name: str) -> str | None:
        session = self._tool_to_session.get(name)
        if not session:
            return None
        server_name = self._session_to_server_name.get(session)
        return server_name

    def component_name_hook(self, name: str, serverinfo: types.Implementation) -> str:
        """Custom Component Name Hook for ClientSessionGroup base class"""
        self._tool_to_serverinfo[name] = serverinfo
        server_name = self._server_info_to_server_name.get(serverinfo_str(serverinfo))
        new_name = f"{server_name}:{name}"
        log.debug(f"component rename: {name} -> {new_name}")
        return new_name

    @validate_call
    async def connect_to_server(self, server_params: ServerParameters) -> NotImplementedError:
        raise NotImplementedError("Use connect_to_server_with_name instead")

    @validate_call
    async def connect_to_server_with_name(
        self,
        server_name: str,
        server_params: ServerParameters,
    ) -> mcp.ClientSession:
        """Connects to a single MCP server."""
        log.info(f"connecting to server - server_name={server_name}")
        server_info: mcp.types.Implementation
        session: mcp.ClientSession
        server_info, session = await self._establish_session(server_params)
        await self.connect_with_session(server_info, session)

        self._server_info_to_server_name[serverinfo_str(server_info)] = server_name
        self._session_to_server_name[session] = server_name
        return session
