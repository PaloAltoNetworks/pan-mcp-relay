"""Unit tests for Configuration class."""
import json
import tempfile
import os
import pytest
from unittest.mock import patch
from pan_aisecurity_mcp.mcp_relay.configuration import Configuration


class TestConfiguration:
    """Basic unit tests for Configuration class."""

    @patch('pan_aisecurity_mcp.mcp_relay.configuration.load_dotenv')
    def test_init_calls_load_env(self, mock_load_dotenv):
        """Test that __init__ calls load_env method."""
        Configuration()
        mock_load_dotenv.assert_called_once()

    def test_load_config_valid_json_file(self):
        """Test loading a valid JSON configuration file."""
        test_config = {
            "server_name": "test-server",
            "port": 8080,
            "debug": True
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_config, f)
            temp_file_path = f.name

        try:
            result = Configuration.load_config(temp_file_path)
            assert result == test_config
            assert isinstance(result, dict)
        finally:
            os.unlink(temp_file_path)

    def test_load_config_file_not_found(self):
        """Test that FileNotFoundError is raised for non-existent file."""
        non_existent_path = "/path/that/does/not/exist.json"

        with pytest.raises(FileNotFoundError):
            Configuration.load_config(non_existent_path)




