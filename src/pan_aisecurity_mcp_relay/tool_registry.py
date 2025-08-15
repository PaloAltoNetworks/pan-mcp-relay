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

import json
import logging
from datetime import datetime, timedelta
from typing import Any

from pan_aisecurity_mcp_relay.constants import (
    TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT,
    UNIX_EPOCH,
)
from pan_aisecurity_mcp_relay.exceptions import AISecMcpRelayToolRegistryError, AISecMcpRelayValidationError
from pan_aisecurity_mcp_relay.tool import InternalTool, ToolState

logger = logging.getLogger(__name__)


class ToolRegistry:
    """A registry for managing and caching internal tools with expiration-based refresh logic.

    The ToolRegistry maintains collections of tools, provides filtering capabilities,
    and includes caching mechanisms to optimize performance. It supports operations
    like retrieving available tools, mapping tools by server, and tool lookup by hash.
    """

    def __init__(self, tool_registry_cache_expiry: int = TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT) -> None:
        """
        Initialize the ToolRegistry with empty collections and cache settings.

        Args:
            tool_registry_cache_expiry: Cache expiration time in seconds
                                      (default: TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT seconds)

        Raises:
            AISecMcpRelayException: VALIDATION_ERROR: If cache expiry is invalid
        """
        if tool_registry_cache_expiry <= 0:
            raise AISecMcpRelayValidationError("Tool registry cache expiry must be a positive integer")

        self._internal_tool_list: list[InternalTool] = []
        self._available_tool_list: list[InternalTool] = []
        self._hash_to_tool_map: dict[str, InternalTool] = {}
        self._last_updated_at: datetime = UNIX_EPOCH
        self._expiry_in_seconds: int = tool_registry_cache_expiry

        logger.info(
            "Tool registry initialized with cache expiry %d seconds.",
            self._expiry_in_seconds,
        )

    def update_registry(self, internal_tool_list: list[InternalTool]) -> None:
        """
        Update the registry with a new list of tools and refresh all internal collections.

        This method replaces the current tool list, rebuilds the available tools filter,
        updates the hash-to-tool mapping, and refreshes the last updated timestamp.

        Args:
            internal_tool_list: New list of InternalTool objects to register

        Raises:
            AISecMcpRelayException: VALIDATION_ERROR: If internal_tool_list is None or invalid
                                    RegistryError: If registry update operation fails
        """
        if internal_tool_list is None:
            raise AISecMcpRelayValidationError("Tool list cannot be None")

        if not isinstance(internal_tool_list, list):
            raise AISecMcpRelayValidationError("Tool list must be a list")

        try:
            self._internal_tool_list = internal_tool_list
            self._update_available_tools()
            self._update_hash_mapping()
            self._last_updated_at = datetime.now()

            logger.info(
                "Tool registry updated at %s with %d tools (%d available).",
                self._last_updated_at,
                len(self._internal_tool_list),
                len(self._available_tool_list),
            )
        except Exception as e:
            raise AISecMcpRelayToolRegistryError(f"Failed to update tool registry {e}")

    def _update_available_tools(self) -> None:
        """Update the available tools list with only enabled tools."""
        self._available_tool_list = [tool for tool in self._internal_tool_list if tool.state == ToolState.ENABLED]

    def _update_hash_mapping(self) -> None:
        """Update the hash-to-tool mapping for quick lookups."""
        self._hash_to_tool_map.clear()
        for tool in self._internal_tool_list:
            if tool.sha256_hash:  # Ensure hash exists
                self._hash_to_tool_map[tool.sha256_hash] = tool

    def is_registry_outdated(self) -> bool:
        """
        Check if the registry cache has expired and needs to be refreshed.

        Returns:
            bool: True if the registry is outdated (past expiry time), False otherwise
        """
        time_elapsed = datetime.now() - self._last_updated_at
        return time_elapsed > timedelta(seconds=self._expiry_in_seconds)

    def get_available_tools(self) -> list[InternalTool]:
        """
        Retrieve all tools that are currently in the ENABLED state.

        Returns:
            list[InternalTool]: List of enabled tools available for use
        """
        return self._available_tool_list

    def get_all_tools(self) -> list[InternalTool]:
        """
        Retrieve the complete list of all registered tools regardless of state.

        Returns:
            list[InternalTool]: Complete list of all tools in the registry
        """
        return self._internal_tool_list

    def get_tool_by_hash(self, sha256_hash: str) -> InternalTool | None:
        """
        Look up a specific tool using its SHA256 hash identifier.

        Provides fast O(1) lookup for tools when the hash is known,
        useful for tool identification and retrieval operations.

        Args:
            sha256_hash: The SHA256 hash string identifying the desired tool

        Returns:
            Optional[InternalTool]: The tool object if found, None if hash doesn't exist

        Raises:
            ValidationError: If sha256_hash is invalid
        """
        if not isinstance(sha256_hash, str):
            raise AISecMcpRelayValidationError("SHA256 hash must be a string")

        if not sha256_hash:
            return None

        return self._hash_to_tool_map.get(sha256_hash)

    def get_server_tool_map(self) -> dict[str, list[InternalTool]]:
        """
        Group all tools by their server name for organized access.

        Creates a mapping where each server name points to a list of tools
        that belong to that server, including both enabled and disabled tools.

        Returns:
            dict[str, list[InternalTool]]: Dictionary mapping server names to their tool lists
        """
        # TODO: Use defaultdict
        server_tool_map: dict[str, list[InternalTool]] = {}

        for tool in self._internal_tool_list:
            server_name = tool.server_name
            # TODO: Use defaultdict
            if server_name not in server_tool_map:
                server_tool_map[server_name] = []
            server_tool_map[server_name].append(tool)

        return server_tool_map

    def get_server_tool_map_json(self) -> str:
        """
        Get the server-to-tools mapping as a JSON string representation.

        Converts the server tool mapping to a nested JSON structure where
        each server's tools are serialized as JSON strings within the main JSON object.

        Returns:
            str: JSON string containing the server-to-tools mapping with pretty formatting

        Raises:
            AISecMcpRelayException: json.JSONEncodeError: If tools cannot be serialized to JSON
        """
        try:
            server_tool_map = self.get_server_tool_map()
            serializable = {
                server_name: [tool.model_dump() for tool in tool_list]
                for server_name, tool_list in server_tool_map.items()
            }
            return json.dumps(serializable, indent=2, ensure_ascii=False)

        except (AttributeError, TypeError) as e:
            logger.error("Failed to serialize tools to JSON: %s", e)
            raise AISecMcpRelayToolRegistryError(f"Tool serialization failed {e}")

    def get_registry_stats(self) -> dict[str, Any]:
        """
        Get statistics about the current registry state.

        Returns:
            dict[str, any]: Dictionary containing registry statistics
        """
        server_count = len(set(tool.server_name for tool in self._internal_tool_list))

        return {
            "total_tools": len(self._internal_tool_list),
            "available_tools": len(self._available_tool_list),
            "server_count": server_count,
            "last_updated": self._last_updated_at.isoformat(),
            "is_outdated": self.is_registry_outdated(),
            "cache_expiry_seconds": self._expiry_in_seconds,
        }

    def clear_registry(self) -> None:
        """
        Clear all tools from the registry and reset timestamps.
        """
        self._internal_tool_list.clear()
        self._available_tool_list.clear()
        self._hash_to_tool_map.clear()
        self._last_updated_at = UNIX_EPOCH

        logger.info("Tool registry cleared.")

    def __len__(self) -> int:
        """Return the total number of tools in the registry."""
        return len(self._internal_tool_list)

    def __contains__(self, sha256_hash: str) -> bool:
        """Check if a tool with the given hash exists in the registry."""
        return sha256_hash in self._hash_to_tool_map

    def __repr__(self) -> str:
        """Return string representation of the registry."""
        return (
            f"ToolRegistry(total_tools={len(self._internal_tool_list)}, "
            f"available_tools={len(self._available_tool_list)}, "
            f"last_updated={self._last_updated_at})"
        )
