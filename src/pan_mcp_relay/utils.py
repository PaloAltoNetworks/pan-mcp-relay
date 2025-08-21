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
import functools
import logging
import os
import sys
from pathlib import Path

import click

from .constants import MCP_RELAY_NAME


def expand_path[T](p: T) -> Path | T:
    """Normnalize, Expands environment variables and converts a path string to Path object."""
    if isinstance(p, str):
        p = p.strip()
    if not p:
        return p
    p = expand_vars(p)
    p = Path(p)
    p = p.expanduser()
    p = p.resolve()
    return p


def expand_vars(value: str) -> str:
    """Expand shell variables of form $var and ${var}."""
    return os.path.expandvars(value)


def getenv(key: str, masked: bool = False) -> str:
    value = os.getenv(key, "")
    if value and masked:
        return "*****"
    return value


def deep_merge[K, V](original: dict[K, V], *updaters: dict[K, V]) -> dict[K, V]:
    original = original.copy()
    for update in updaters:
        for k, v in update.items():
            if k in original and isinstance(original[k], dict) and isinstance(v, dict):
                original[k] = deep_merge(original[k], v)
            else:
                original[k] = v
    return original


def get_logger(name: str) -> logging.Logger:
    prefix = MCP_RELAY_NAME
    if name == "__main__" or name == __package__:
        return logging.getLogger(prefix)
    name = name.replace(__package__, MCP_RELAY_NAME)
    name = name.replace("_", "-")
    return logging.getLogger(name)


@functools.cache
def get_app_dir() -> Path:
    if sys.platform.startswith("win"):
        app_dir = Path(click.get_app_dir(MCP_RELAY_NAME))
    else:
        # Prefer ~/.config/pan-mcp-relay if we can
        xdg_config = Path.home() / ".config"
        if xdg_config.exists() and xdg_config.resolve().is_dir():
            app_dir = Path(xdg_config) / f".{MCP_RELAY_NAME.lower()}"
        else:
            return Path(click.get_app_dir(MCP_RELAY_NAME))
    return app_dir
