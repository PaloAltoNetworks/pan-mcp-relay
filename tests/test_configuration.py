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

"""Unit tests for Configuration class."""

import json
import os
import tempfile
from unittest.mock import patch

import pytest

from pan_aisecurity_mcp_relay.configuration import Configuration


class TestConfiguration:
    """Basic unit tests for Configuration class."""

    @patch("pan_aisecurity_mcp_relay.configuration.load_dotenv")
    def test_init_calls_load_env(self, mock_load_dotenv):
        """Test that __init__ calls load_env method."""
        Configuration()
        mock_load_dotenv.assert_called_once()

    def test_load_config_valid_json_file(self):
        """Test loading a valid JSON configuration file."""
        test_config = {"server_name": "test-server", "port": 8080, "debug": True}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
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
