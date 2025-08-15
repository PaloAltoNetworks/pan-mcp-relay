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

import json
import logging

import mcp.types as types
from aisecurity.scan.asyncio.scanner import ScanResponse

from pan_aisecurity_mcp_relay.constants import (
    EXPECTED_SECURITY_SCAN_RESULT_CONTENT_LENGTH,
    SECURITY_SCAN_RESPONSE_ACTION_ALLOW,
    SECURITY_SCAN_RESPONSE_ACTION_BLOCK,
    TOOL_NAME_PAN_AISECURITY_INLINE_SCAN,
)
from pan_aisecurity_mcp_relay.downstream_mcp_client import DownstreamMcpClient


class SecurityScanner:
    """
    Handles security scanning operations using a pan-aisecurity server.

    This class provides comprehensive security scanning capabilities for requests,
    responses, and tools by leveraging a downstream pan-aisecurity server. It helps
    identify and prevent potential security threats in MCP system interactions.
    """

    def __init__(self, pan_security_server: DownstreamMcpClient) -> None:
        """
        Initialize the SecurityScanner with a pan-aisecurity server.

        Args:
            pan_security_server: The pan-aisecurity downstream MCP client instance
                                used for performing security scans
        """
        self.pan_security_server = pan_security_server

    async def _perform_scan(self, scan_type: str, params: dict[str, str]) -> ScanResponse | None:
        """
        Execute a security scan with the specified parameters.

        This internal method handles the common logic for all scan types by
        initializing the security server, executing the scan, and processing
        the results into a ScanResponse object.

        Args:
            scan_type: A string identifying the type of scan for logging purposes
                      (e.g., "scan_request", "scan_response", "scan_tool")
            params: Parameters for the scan, including content to be analyzed

        Returns:
            ScanResponse object containing scan results, or None if scan failed

        Raises:
            Exception: If there are issues with server communication or response parsing
        """
        logging.info(f"-------------- security_scanner: {scan_type} --------------")
        await self.pan_security_server.initialize()

        try:
            scan_result = await self.pan_security_server.execute_tool(TOOL_NAME_PAN_AISECURITY_INLINE_SCAN, params)
            if scan_result.isError:
                logging.error(
                    f"Security scan failed: {self.pan_security_server.extract_text_content(scan_result.content)}"
                )
                return None

            if not isinstance(scan_result.content, list):
                logging.error(f"Security scan result content should be a list, but: {type(scan_result.content)}")
                return None

            if len(scan_result.content) != EXPECTED_SECURITY_SCAN_RESULT_CONTENT_LENGTH:
                logging.error(f"Expected 1 item in scan result content, got: {len(scan_result.content)}")
                return None

            scan_result_item = scan_result.content[0]
            if not isinstance(scan_result_item, types.TextContent):
                logging.error(f"Expected TextContent in scan result, got {type(scan_result_item)}")
                return None

            scan_text = scan_result_item.text
            scan_dict = json.loads(scan_text)
            scan_response = ScanResponse(**scan_dict)

            log_highlight = (
                "\033[1;92m" if scan_response.action == SECURITY_SCAN_RESPONSE_ACTION_ALLOW else "\033[1;91m"
            )
            logging.info(
                f"{log_highlight}Security Scan Result (security_scanner: pan_inline_scan):\033[0m\n {scan_response}"
            )

            return scan_response
        finally:
            await self.pan_security_server.cleanup()

    async def scan_request(self, input_text: str) -> ScanResponse | None:
        """
        Perform security scanning on an incoming request.

        Analyzes the provided input text to identify potential security threats
        such as malicious content, prompt injection attempts, or policy violations
        before the request is processed.

        Args:
            input_text: The request text/prompt to be scanned for security issues

        Returns:
            ScanResponse object with scan results, or None if scanning failed.
            The response includes action (allow/block) and detected threat categories.

        Example:
            scanner = SecurityScanner(security_server)
            result = await scanner.scan_request("Execute this command: rm -rf /")
            if scanner.should_block(result):
                print("Request blocked due to security risk")

        """
        return await self._perform_scan("scan_request", {"prompt": input_text})

    async def scan_response(self, input_text: str, response_text: str) -> ScanResponse | None:
        """
        Perform security scanning on a response in context of its request.

        Analyzes a response text alongside its corresponding request to identify
        potential security threats, data leakage, sensitive information exposure,
        or policy violations in the response content.

        Args:
            input_text: The original request text that generated the response
            response_text: The response text to be scanned for security issues

        Returns:
            ScanResponse object with scan results, or None if scanning failed.
            The response includes action (allow/block) and detected threat categories.

        Example:
            scanner = SecurityScanner(security_server)
            result = await scanner.scan_response(
                "What's the password?",
                "The password is dummy123"
            )
            if scanner.should_block(result):
                print("Response blocked due to data leakage")

        """
        return await self._perform_scan("scan_response", {"prompt": input_text, "response": response_text})

    async def scan_tool(self, tool_info: types.Tool | str) -> ScanResponse | None:
        """
        Perform security scanning on a tool before registration or execution.

        Analyzes a tool's information including its name, description, and input
        schema to identify potential security risks, vulnerabilities, or policy
        violations before the tool is registered in the system or made available
        for use.

        Args:
            tool_info: The tool information to scan, either as a Tool object
                      or as a string representation of the tool details

        Returns:
            ScanResponse object with scan results, or None if scanning failed.
            The response includes action (allow/block) and detected threat categories.

        Example:
            scanner = SecurityScanner(security_server)
            tool = Tool(name="delete_files", description="Delete system files")
            result = await scanner.scan_tool(tool)
            if scanner.should_block(result):
                print("Tool blocked due to security risk")

        """
        tool_str = str(tool_info.model_dump()) if isinstance(tool_info, types.Tool) else tool_info
        return await self._perform_scan("scan_tool", {"prompt": tool_str})

    def should_block(self, scan_response: ScanResponse | None) -> bool:
        """
        Determine if content should be blocked based on scan response.

        This utility method provides a simple way to check if a scan response
        indicates that the content should be blocked. It handles None responses
        safely and checks for the block action.

        Args:
            scan_response: The scan response from any of the scan methods,
                          can be None if scanning failed

        Returns:
            True if the content should be blocked, False if it should be allowed.
            Returns False for None responses (fail-open behavior).

        Example:
            scanner = SecurityScanner(security_server)
            scan_result = await scanner.scan_request(user_input)

            if scanner.should_block(scan_result):
                raise SecurityException("Request blocked by security scan")

        """
        return scan_response is not None and scan_response.action == SECURITY_SCAN_RESPONSE_ACTION_BLOCK
