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
        with open(file_path, "r") as f:
            return json.load(f)
