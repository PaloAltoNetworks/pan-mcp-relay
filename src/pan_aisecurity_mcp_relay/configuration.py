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
from typing import Any

from dotenv import load_dotenv


class Configuration:
    """Manages configuration and environment variables for the MCP relay."""

    def __init__(self) -> None:
        """
        Initialize the Configuration instance.

        Automatically loads environment variables from a .env file upon initialization.
        """
        self.load_env()

    @staticmethod
    def load_env() -> None:
        """
        Load environment variables from a `.env` file.

        This allows configuration values to be set via environment rather than hardcoded.
        Uses `python-dotenv` to read the `.env` file into the process environment.
        """
        load_dotenv()

    @staticmethod
    def load_config(file_path: str) -> dict[str, Any]:
        """
        Load configuration from a JSON file.

        Args:
            file_path: The path to the JSON configuration file.

        Returns:
            A dictionary representing the configuration loaded from the file.

        Raises:
            FileNotFoundError: If the file does not exist at the given path.
            json.JSONDecodeError: If the file contains invalid JSON.
        """
        with open(file_path) as f:
            return json.load(f)
