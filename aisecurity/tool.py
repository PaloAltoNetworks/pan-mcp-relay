"""
Tool module for MCP Relay application.

Defines tool classes and states for managing tools across different servers.
"""

from enum import Enum
import hashlib
import json
from typing import Any, List
import mcp.types as types
from pydantic import ConfigDict, Field


class ToolState(str, Enum):
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

    def get_argument_descriptions(self) -> List[str]:
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
                line = f"- {param_name}: {desc}"
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
        return types.Tool(
            name=self.name, 
            description=self.description, 
            inputSchema=self.inputSchema, 
            annotations=self.annotations
        )


class InternalTool(BaseTool):
    """
    Internal tool with hash-based identification.
    
    Extends BaseTool with MD5 hash for tool identification and caching.
    """

    md5_hash: str = Field(default="", description="Hash of tool identity fields")

    def model_post_init(self, __context: Any) -> None:
        """Compute hash after initialization."""
        self.md5_hash = self.compute_hash()

    def compute_hash(self) -> str:
        """
        Compute MD5 hash of tool identity fields.
        
        Returns:
            MD5 hash string.
        """
        payload = {
            "server_name": self.server_name,
            "tool_name": self.name,
            "description": self.description,
            "input_schema": self.inputSchema,
        }
        json_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.md5(json_str.encode("utf-8")).hexdigest()
    
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
            "md5_hash": self.md5_hash,
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

        return f"""
Tool: {self.name}
Server: {self.server_name}
Description: {self.description}
Arguments:
{chr(10).join(args_desc)}
"""