"""
Tool Registry Module

This module provides the ToolRegistry class for managing and caching internal tools
with expiration-based refresh logic and efficient lookup capabilities.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json
import logging

from constants import TOOL_REGISTRY_CACHE_EXPIRY_DEFAULT, UNIX_EPOCH
from tool import InternalTool, ToolState
from exceptions import AISecMcpRelayException, ErrorType


logger = logging.getLogger(__name__)


class ToolRegistry:
    """
    A registry for managing and caching internal tools with expiration-based refresh logic.
    
    The ToolRegistry maintains collections of tools, provides filtering capabilities,
    and includes caching mechanisms to optimize performance. It supports operations
    like retrieving available tools, mapping tools by server, and tool lookup by hash.
    
    Attributes:
        internal_tool_list: Complete list of all registered internal tools
        available_tool_list: Filtered list containing only enabled tools
        hash_to_tool_map: Dictionary mapping MD5 hashes to tools for quick lookup
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
            raise AISecMcpRelayException(
                "Tool registry cache expiry must be a positive integer",
                ErrorType.VALIDATION_ERROR
            )
            
        self._internal_tool_list: List[InternalTool] = []
        self._available_tool_list: List[InternalTool] = []
        self._hash_to_tool_map: Dict[str, InternalTool] = {}
        self._last_updated_at: datetime = UNIX_EPOCH
        self._expiry_in_seconds: int = tool_registry_cache_expiry
        
        logger.info(
            "Tool registry initialized with cache expiry %d seconds.",
            self._expiry_in_seconds
        )

    def update_registry(self, internal_tool_list: List[InternalTool]) -> None:
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
            raise AISecMcpRelayException(
                    "Tool list cannot be None",
                    ErrorType.VALIDATION_ERROR
                )
            
        if not isinstance(internal_tool_list, list):
            raise AISecMcpRelayException(
                "Tool list must be a list",
                ErrorType.VALIDATION_ERROR
            )
            
        try:
            self._internal_tool_list = internal_tool_list
            self._update_available_tools()
            self._update_hash_mapping()
            self._last_updated_at = datetime.now()
            
            logger.info(
                "Tool registry updated at %s with %d tools (%d available).",
                self._last_updated_at,
                len(self._internal_tool_list),
                len(self._available_tool_list)
            )
        except Exception as e:
            raise AISecMcpRelayException(
                f"Failed to update tool registry {e}",
                ErrorType.TOOL_REGISTRY_ERROR
            )

    def _update_available_tools(self) -> None:
        """Update the available tools list with only enabled tools."""
        self._available_tool_list = [
            tool for tool in self._internal_tool_list 
            if tool.state == ToolState.ENABLED
        ]

    def _update_hash_mapping(self) -> None:
        """Update the hash-to-tool mapping for quick lookups."""
        self._hash_to_tool_map.clear()
        for tool in self._internal_tool_list:
            if tool.md5_hash:  # Ensure hash exists
                self._hash_to_tool_map[tool.md5_hash] = tool

    def is_registry_outdated(self) -> bool:
        """
        Check if the registry cache has expired and needs to be refreshed.
        
        Returns:
            bool: True if the registry is outdated (past expiry time), False otherwise
        """ 
        time_elapsed = datetime.now() - self._last_updated_at
        return time_elapsed > timedelta(seconds=self._expiry_in_seconds)

    def get_available_tools(self) -> List[InternalTool]:
        """
        Retrieve all tools that are currently in the ENABLED state.
        
        Returns:
            List[InternalTool]: List of enabled tools available for use
        """
        return self._available_tool_list

    def get_all_tools(self) -> List[InternalTool]:
        """
        Retrieve the complete list of all registered tools regardless of state.
        
        Returns:
            List[InternalTool]: Complete list of all tools in the registry
        """
        return self._internal_tool_list

    def get_tool_by_hash(self, md5_hash: str) -> Optional[InternalTool]:
        """
        Look up a specific tool using its MD5 hash identifier.
        
        Provides fast O(1) lookup for tools when the hash is known,
        useful for tool identification and retrieval operations.
        
        Args:
            md5_hash: The MD5 hash string identifying the desired tool
            
        Returns:
            Optional[InternalTool]: The tool object if found, None if hash doesn't exist
            
        Raises:
            ValidationError: If md5_hash is invalid
        """
        if not isinstance(md5_hash, str):
            raise AISecMcpRelayException(
                "MD5 hash must be a string",
                ErrorType.VALIDATION_ERROR
            )
            
        if not md5_hash:
            return None
            
        return self._hash_to_tool_map.get(md5_hash)

    def get_server_tool_map(self) -> Dict[str, List[InternalTool]]:
        """
        Group all tools by their server name for organized access.
        
        Creates a mapping where each server name points to a list of tools
        that belong to that server, including both enabled and disabled tools.
        
        Returns:
            Dict[str, List[InternalTool]]: Dictionary mapping server names to their tool lists
        """
        server_tool_map: Dict[str, List[InternalTool]] = {}

        for tool in self._internal_tool_list:
            server_name = tool.server_name
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
            raise AISecMcpRelayException(
                f"Tool serialization failed {e}",
                ErrorType.TOOL_REGISTRY_ERROR
            )

    def get_registry_stats(self) -> Dict[str, any]:
        """
        Get statistics about the current registry state.
        
        Returns:
            Dict[str, any]: Dictionary containing registry statistics
        """
        server_count = len(set(tool.server_name for tool in self._internal_tool_list))
        
        return {
            "total_tools": len(self._internal_tool_list),
            "available_tools": len(self._available_tool_list),
            "server_count": server_count,
            "last_updated": self._last_updated_at.isoformat(),
            "is_outdated": self.is_registry_outdated(),
            "cache_expiry_seconds": self._expiry_in_seconds
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

    def __contains__(self, md5_hash: str) -> bool:
        """Check if a tool with the given hash exists in the registry."""
        return md5_hash in self._hash_to_tool_map

    def __repr__(self) -> str:
        """Return string representation of the registry."""
        return (
            f"ToolRegistry(total_tools={len(self._internal_tool_list)}, "
            f"available_tools={len(self._available_tool_list)}, "
            f"last_updated={self._last_updated_at})"
        )
