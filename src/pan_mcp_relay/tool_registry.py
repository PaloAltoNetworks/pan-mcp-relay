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
Tool Registry Module

This module provides the ToolRegistry class for managing and caching internal tools
with expiration-based refresh logic and efficient lookup capabilities.
"""

from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field, validate_call

from . import utils
from .configuration import McpRelayConfig
from .constants import (
    TOOL_REGISTRY_CACHE_TTL_DEFAULT,
    UNIX_EPOCH,
)
from .exceptions import (
    McpRelayInternalError,
    McpRelayToolRegistryError,
)
from .tool import InternalTool, ToolState

log = utils.get_logger(__name__)


class ToolRegistry(BaseModel):
    """A registry for managing and caching internal tools with expiration-based refresh logic.

    The ToolRegistry maintains collections of tools, provides filtering capabilities,
    and includes caching mechanisms to optimize performance. It supports operations
    like retrieving available tools, mapping tools by server, and tool lookup by hash.
    """

    config: McpRelayConfig = None
    refresh_interval: int = Field(default=TOOL_REGISTRY_CACHE_TTL_DEFAULT, init=False)
    tools: dict[str, InternalTool] = Field(default_factory=dict, init=False)
    available_tools: dict[str, InternalTool] = Field(default_factory=dict, init=False)
    tools_by_checksum: dict[str, InternalTool] = Field(default_factory=dict, init=False)
    last_update: datetime = Field(default=UNIX_EPOCH, init=False)

    def model_post_init(self, context: Any, /) -> None:
        """Post-initialization hook for tool registry."""
        self.refresh_interval = self.config.tool_registry_cache_ttl
        log.info(
            "Tool registry initialized with refresh period of %d seconds.",
            self.refresh_interval,
        )

    @validate_call
    def update_registry(self, tools: dict[str, InternalTool]) -> None:
        """
        Update the registry with a new list of tools and refresh all internal collections.

        This method replaces the current tool list, rebuilds the available tools filter,
        updates the hash-to-tool mapping, and refreshes the last updated timestamp.

        Args:
            tools: New list of InternalTool objects to register

        Raises:
            McpRelayInternalError: If internal_tool_list is None or invalid
            McpRelayToolRegistryError: If registry update operation fails
        """
        if tools is None:
            raise McpRelayInternalError("Tool list cannot be None")
        if not tools:
            log.warning("Update registry failed: no tools found")

        log.debug(f"Updating tool registry with {len(tools)} internal tools")
        try:
            self.tools = tools
            self.update_available_tools()
            self.update_hash_mapping()
            self.last_update = datetime.now()

            log.info(
                "Tool registry updated at %s with %d tools (%d available).",
                self.last_update,
                len(self.tools),
                len(self.available_tools),
            )
        except Exception as e:
            raise McpRelayToolRegistryError("Failed to update tool registry") from e

    def update_available_tools(self) -> None:
        """Update the available tools list with only enabled tools."""
        self.available_tools.clear()
        for tool_name, tool in self.tools.items():
            if tool.state == ToolState.ENABLED:
                log_handler = log.debug
                self.available_tools[tool_name] = tool
            else:
                log_handler = log.info
            log_handler(f"[tool_registry.update]: {tool_name}: {tool.state}")

    def update_hash_mapping(self) -> None:
        """Update the hash-to-tool mapping for quick lookups."""
        self.tools_by_checksum.clear()
        for tool_name, tool in self.tools.items():
            if tool.sha256_hash:  # Ensure hash exists
                self.tools_by_checksum[tool.sha256_hash] = tool
            else:
                log.warning(f"Tool {tool_name} is missing sha256_hash")

    def is_registry_outdated(self) -> bool:
        """
        Check if the registry cache has expired and needs to be refreshed.

        Returns:
            bool: True if the registry is outdated (past expiry time), False otherwise
        """
        time_elapsed = datetime.now() - self.last_update
        is_oudated = time_elapsed > timedelta(seconds=self.refresh_interval)
        if is_oudated:
            log.debug("tool registry cache expired ({time_elapsed})")
        return is_oudated

    def get_available_tools(self) -> dict[str, InternalTool]:
        """
        Retrieve all tools that are currently in the ENABLED state.

        Returns:
            list[InternalTool]: List of enabled tools available for use
        """
        return self.available_tools

    def get_all_tools(self) -> dict[str, InternalTool]:
        """
        Retrieve the complete list of all registered tools regardless of state.

        Returns:
            list[InternalTool]: Complete list of all tools in the registry
        """
        return self.tools

    @validate_call
    def get_tool_by_hash(self, sha256_hash: str) -> InternalTool | None:
        """
        Look up a specific tool using its SHA256 hash identifier.

        Provides fast O(1) lookup for tools when the hash is known,
        useful for tool identification and retrieval operations.

        Args:
            sha256_hash: The SHA256 hash string identifying the desired tool

        Returns:
            Optional[InternalTool]: The tool object if found, None if hash doesn't exist
        """
        return self.tools_by_checksum.get(sha256_hash)

    def get_registry_stats(self) -> dict[str, Any]:
        """
        Get statistics about the current registry state.

        Returns:
            dict[str, any]: Dictionary containing registry statistics
        """
        return {
            "total_tools": len(self.tools),
            "available_tools": len(self.available_tools),
            "last_updated": self.last_update.isoformat(),
            "is_outdated": self.is_registry_outdated(),
            "cache_expiry_seconds": self.refresh_interval,
        }

    def clear_registry(self) -> None:
        """
        Clear all tools from the registry and reset timestamps.
        """
        self.tools.clear()
        self.available_tools.clear()
        self.tools_by_checksum.clear()
        self.last_update = UNIX_EPOCH

        log.info("Tool registry cleared.")

    def __len__(self) -> int:
        """Return the total number of tools in the registry."""
        return len(self.tools)

    def __contains__(self, sha256_hash: str) -> bool:
        """Check if a tool with the given hash exists in the registry."""
        return sha256_hash in self.tools_by_checksum

    def __repr__(self) -> str:
        """Return string representation of the registry."""
        return (
            f"ToolRegistry(total_tools={len(self.tools)}, "
            f"available_tools={len(self.available_tools)}, "
            f"last_updated={self.last_update})"
        )
