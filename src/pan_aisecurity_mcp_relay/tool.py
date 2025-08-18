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
import json
import string
from enum import StrEnum
from typing import Annotated, Any

import mcp.types as types
from pydantic import ConfigDict, Field, StringConstraints, computed_field

from . import utils

log = utils.get_logger(__name__)


class ToolState(StrEnum):
    """Tool state enumeration."""

    ENABLED = "enabled"
    DISABLED_HIDDEN_MODE = "disabled - hidden_mode"
    DISABLED_DUPLICATE = "disabled - duplicate"
    DISABLED_SECURITY_RISK = "disabled - security risk"
    DISABLED_ERROR = "disabled - error"


class BaseTool(types.Tool):
    """
    Base tool class with server info and state.

    Extends MCP Tool with server name and state tracking.
    """

    server_name: str = Field(..., description="The server where this tool is deployed")
    state: ToolState = Field(default=ToolState.ENABLED, description="The state of the tool")

    model_config = ConfigDict(extra="allow")

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

    def to_mcp_tool(self) -> types.Tool:
        """
        Convert to standard MCP Tool.

        Returns:
            Standard MCP Tool object.
        """
        return types.Tool(**self.model_dump(exclude={"server_name", "state"}))

    @computed_field
    @property
    def server_tool_name(self) -> str:
        """Fully Qualified name of the Tool, prefixed by 'server_name:'"""
        return f"{self.server_name}:{self.name}"


sha256_re = f"^[{string.hexdigits}]" + "{64}$"


class InternalTool(BaseTool):
    """
    Internal tool with hash-based identification.

    Extends BaseTool with SHA256 hash for tool identification and caching.
    """

    sha256_hash: Annotated[
        str | None, StringConstraints(to_lower=True, min_length=64, max_length=64, pattern=sha256_re)
    ] = None

    def model_post_init(self, __context: Any) -> None:
        """Compute hash after initialization."""
        self.sha256_hash = self.compute_hash()

    def compute_hash(self) -> str:
        """
        Compute SHA256 hash of tool identity fields.

        Returns:
            SHA256 hash string.
        """
        payload = {
            "server_name": self.server_name,
            "tool_name": self.name,
            "description": self.description,
            "input_schema": self.inputSchema,
        }
        json_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(json_str.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, str]:
        """
        Convert tool to dictionary.

        Returns:
            Dictionary representation of the tool.
        """
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.inputSchema,
            "server_name": self.server_name,
            "state": self.state,
            "sha256_hash": self.sha256_hash,
        }


class RelayTool(BaseTool):
    """
    Tool for LLM presentation and relay operations.

    Extends BaseTool with formatting capabilities for LLM consumption.
    """

    def format_for_llm(self) -> str:
        """
        Format tool information for LLM consumption.

        Returns:
            Formatted string describing the tool.
        """
        args_desc = self.get_argument_descriptions()

        output_fields = {
            "Tool": self.name,
            "Server": self.server_name,
            "Description": self.description,
            "Arguments": f"\n{'\n'.join(args_desc)}",
        }

        text = "\n".join((f"{k}: {v}" for k, v in output_fields.items()))

        return text
