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
Tool module for MCP Relay application.

Defines tool classes and states for managing tools across different servers.
"""

import hashlib
import string
from enum import StrEnum
from typing import Annotated, Any

import mcp.types as types
from pydantic import ConfigDict, Field, StringConstraints

from . import utils

log = utils.get_logger(__name__)

sha256_re = f"^[{string.hexdigits}]" + "{64}$"


class ToolState(StrEnum):
    """Tool state enumeration."""

    ENABLED = "enabled"
    DISABLED_HIDDEN_MODE = "disabled - hidden_mode"
    DISABLED_DUPLICATE = "disabled - duplicate"
    DISABLED_SECURITY_RISK = "disabled - security risk"
    DISABLED_ERROR = "disabled - error"


class InternalTool(types.Tool):
    """
    Base tool class with server info and state.

    Extends MCP Tool with server name and state tracking.
    """

    state: ToolState = Field(default=ToolState.ENABLED, description="The state of the tool")
    sha256_hash: Annotated[
        str | None, StringConstraints(to_lower=True, min_length=64, max_length=64, pattern=sha256_re)
    ] = None

    model_config = ConfigDict(extra="allow")

    def model_post_init(self, context: Any, /) -> None:
        self.sha256_hash = self.compute_hash()

    def get_argument_descriptions(self) -> list[str]:
        """
        Get formatted argument descriptions from input schema.

        Returns:
            List of argument description strings.
        """
        args_desc = []
        if "properties" in self.inputSchema:
            required_params = self.inputSchema.get("required", [])
            for param_name, param_info in self.inputSchema["properties"].items():
                desc = param_info.get("description", "No description")
                line = f"  - {param_name}: {desc}"
                if param_name in required_params:
                    line += " (required)"
                args_desc.append(line)
        return args_desc

    def compute_hash(self) -> str:
        """
        Compute SHA256 hash of tool identity fields.

        Returns:
            SHA256 hash string.
        """
        json_str = self.model_dump_json(indent=0, exclude_none=True, exclude_unset=True)
        return hashlib.sha256(json_str.encode("utf-8")).hexdigest()

    def to_mcp_tool(self) -> types.Tool:
        """
        Convert to standard MCP Tool.

        Returns:
            Standard MCP Tool object.
        """
        return types.Tool.model_validate(self.model_dump(include=types.Tool.model_fields.keys()))
