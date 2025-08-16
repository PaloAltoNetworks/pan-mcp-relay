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

import asyncio
import logging
import shutil
import sys
from pathlib import Path

import click
import dotenv
import rich.logging
import yaml
from click.core import ParameterSource
from pydantic import ValidationError
from rich import print

from pan_aisecurity_mcp_relay.configuration import Config
from pan_aisecurity_mcp_relay.exceptions import McpRelayBaseError
from pan_aisecurity_mcp_relay.utils import deep_merge, expand_path, expand_vars, getenv

from .constants import (
    ENV_AI_PROFILE,
    ENV_API_ENDPOINT,
    ENV_API_KEY,
    ENV_CONFIG_FILE,
    ENV_DOTENV,
    ENV_HOST,
    ENV_MAX_SERVERS,
    ENV_MAX_TOOLS,
    ENV_PORT,
    ENV_SHOW_CONFIG,
    ENV_TOOL_CACHE_TTL,
    ENV_TRANSPORT,
    MAX_MCP_SERVERS_DEFAULT,
    MAX_MCP_TOOLS_DEFAULT,
    RELAY_PREFIX,
    TOOL_REGISTRY_CACHE_TTL_DEFAULT,
    TransportType,
)
from .pan_security_relay import PanSecurityRelay

log = logging.getLogger("pan-mcp-relay.main")


def setup_logging():
    """Initialize logging."""
    stderr = rich.console.Console(stderr=True)
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(message)s",
        handlers=[rich.logging.RichHandler(rich_tracebacks=False, console=stderr, markup=True)],
        force=True,
    )


context_settings = {
    "auto_envvar_prefix": RELAY_PREFIX,
    "max_content_width": shutil.get_terminal_size().columns,
    "show_default": True,
}


@click.command(context_settings=context_settings)
@click.option(
    "api_key",
    "-k",
    "--api-key",
    envvar=ENV_API_KEY,
    help=f"Prisma AIRS API Key [{ENV_API_KEY}={getenv(ENV_API_KEY, True)}]",
)
@click.option(
    "api_endpoint",
    "-e",
    "--api-endpoint",
    envvar=ENV_API_ENDPOINT,
    help=f"Prisma AIRS API Endpoint [{ENV_API_ENDPOINT}={getenv(ENV_API_ENDPOINT)}]",
)
@click.option(
    "ai_profile",
    "-p",
    "--ai-profile",
    envvar=ENV_AI_PROFILE,
    help=f"Prisma AIRS AI Profile Name or ID [{ENV_AI_PROFILE}={getenv(ENV_AI_PROFILE)}]",
)
@click.option(
    "config_file",
    "-c",
    "--config-file",
    envvar=ENV_CONFIG_FILE,
    help=f"Path to configuration file (yaml, json) [{ENV_CONFIG_FILE}={getenv(ENV_CONFIG_FILE)}]",
)
@click.option(
    "transport",
    "-t",
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default="stdio",
    help=f"Transport protocol to use [{ENV_TRANSPORT}={getenv(ENV_TRANSPORT)}]",
)
@click.option(
    "host", "-h", "--host", default="127.0.0.1", help=f"Host for HTTP/SSE server [{ENV_HOST}={getenv(ENV_HOST)}]"
)
@click.option(
    "port", "-p", "--port", type=int, default=8000, help=f"Port for HTTP/SSE server [{ENV_PORT}={getenv(ENV_PORT)}]"
)
@click.option(
    "tool_registry_cache_ttl",
    "-t",
    "--tool-registry-cache-ttl",
    type=int,
    default=TOOL_REGISTRY_CACHE_TTL_DEFAULT,
    help=f"Tool registry cache TTL (in seconds) [{ENV_TOOL_CACHE_TTL}={getenv(ENV_TOOL_CACHE_TTL)}]",
)
@click.option(
    "max_mcp_servers",
    "-m",
    "--max-mcp-servers",
    type=int,
    default=MAX_MCP_SERVERS_DEFAULT,
    help=f"Maximum number of downstream MCP servers to allow [{ENV_MAX_SERVERS}={getenv(ENV_MAX_SERVERS)}]",
)
@click.option(
    "max_mcp_tools",
    "-n",
    "--max-mcp-tools",
    type=int,
    default=MAX_MCP_TOOLS_DEFAULT,
    help=f"Maximum number of MCP tools to allow [{ENV_MAX_TOOLS}={getenv(ENV_MAX_TOOLS)}]",
)
@click.option(
    "show_config",
    "--show-config",
    "--dump-config",
    envvar=ENV_SHOW_CONFIG,
    is_flag=True,
    help=f"Show configuration and exit [{ENV_SHOW_CONFIG}={getenv(ENV_SHOW_CONFIG)}]",
)
@click.option(
    "dotenv",
    "--env",
    envvar=ENV_DOTENV,
    help=f"Colon separated search path for, or path to .env file(s) [{ENV_DOTENV}={getenv(ENV_DOTENV)}]",
)
@click.pass_context
def cli(ctx, **kwargs):
    """Command line interface for the MCP relay server."""
    dotenv_search = kwargs.get("dotenv") or ".env"

    try:
        load_dotenvs(dotenv_search)
    except RuntimeError:
        log.exception("event=failed_to_load_dotenv")
        print(dotenv_search)
        return 1
    # Clean up CLI arguments: remove empty strings and null values, expand environment variables
    for k in list(kwargs.keys()):
        if kwargs[k] is None:
            del kwargs[k]
            continue
        elif isinstance(kwargs[k], str):
            if kwargs[k].strip() == "":
                del kwargs[k]
                continue
            kwargs[k] = expand_vars(kwargs[k])
        src = ctx.get_parameter_source(k)
        if src == ParameterSource.DEFAULT:
            del kwargs[k]
            continue

    config_file: Path | None = expand_path(kwargs.get("config_file"))
    config_file = find_config_file(config_file)
    if config_file:
        kwargs["config_file"] = config_file

    cli_vars = {"mcpRelay": kwargs}
    log.debug(f'event="parsed cli variables" data={cli_vars}')

    config_file_data = {}
    if config_file and config_file.exists():
        config_file_data = load_config_file(config_file)
    try:
        file_config = Config(**config_file_data)
        cli_config = Config(**cli_vars)
        file_config_data = file_config.model_dump(exclude_unset=True, exclude_none=True)
        cli_config_data = cli_config.model_dump(exclude_unset=True, exclude_none=True)
        log.debug(f"event=merging_config\nconfig_file={file_config_data}\ncli={cli_config_data}")
        merged_config = deep_merge(
            file_config_data,
            cli_config_data,
        )
        log.debug(f"event=merged_config merged={merged_config}")
        config: Config = Config(**merged_config)
        log.debug(f"event=loaded_config config={config.model_dump(exclude_unset=True, exclude_none=True)}")
    except ValidationError as e:
        err_msg = 'event="failed to validate configuration"'
        log.exception(err_msg)
        print(config_file_data)
        print(cli_vars)
        raise click.ClickException(err_msg) from e

    if config.mcp_relay.show_config:
        log.info("event=show_config")
        dict_config = config.model_dump(
            mode="json",
            exclude_unset=False,
            exclude_none=False,
            exclude={"mcp_relay": {"show_config", "api_key"}},
            by_alias=True,
        )
        print(yaml.dump(dict_config, sort_keys=False, indent=2))
        return 0

    return asyncio.run(start_mcp_relay_server(config))


async def start_mcp_relay_server(config: Config):
    """Initialize and Start the MCP Relay"""
    mcp_servers_config = {k: v.model_dump() for k, v in config.mcp_servers.items()}
    relay_config = config.mcp_relay

    relay_server = PanSecurityRelay(
        security_scanner_env=relay_config.security_scanner_env(),
        tool_registry_cache_expiry=relay_config.tool_registry_cache_ttl,
        max_downstream_servers=relay_config.max_mcp_servers,
        max_downstream_tools=relay_config.max_mcp_tools,
        mcp_servers_config=mcp_servers_config,
    )
    await relay_server.initialize()
    # Create and run the MCP server
    app = await relay_server.launch_mcp_server()
    match relay_config.transport:
        case TransportType.stdio:
            await relay_server.run_stdio_server(app)
        case TransportType.sse:
            await relay_server.run_sse_server(app, str(relay_config.host), relay_config.port)
        case TransportType.streamable_http:
            log.error("Streamable HTTP transport is not currently supported")
        case _:
            log.error(f"Invalid transport type: {relay_config.transport}")
            return 1

    return 0


def load_dotenvs(dotenv_search):
    if not dotenv_search or not isinstance(dotenv_search, str):
        return
    log.debug(f"Searching for .env files: {dotenv_search}")
    search_paths: list[str] = [p for p in dotenv_search.split(":") if p.strip()]
    loaded_paths: list[Path] = []
    for path in search_paths:
        orig_path = path
        path = Path(path)
        if not path.exists():
            log.debug(f"Skipping non-existent path: {orig_path}")
            continue
        if path.is_dir():
            log.debug(f"Searching for .env file in directory: {orig_path}")
            if (path / ".env").exists():
                path /= ".env"
        if path.is_file():
            log.debug(f"Loading .env file: {path}")
            dotenv.load_dotenv(path, override=False, interpolate=True)
            loaded_paths.append(path)
            continue
        log.debug(f"No env .env file found at {orig_path}")
    if not loaded_paths:
        log.warning(f"No .env files found in search path: {search_paths}")


def find_config_file(config_path: Path | None) -> Path | None:
    search_paths = [Path.cwd(), Path.home() / ".config/pan-mcp-relay"]
    yaml_paths = [p / "mcp-relay.yaml" for p in search_paths]
    json_paths = [p / "mcp-relay.json" for p in search_paths]
    for path in [config_path, *yaml_paths, *json_paths]:
        if path is None:
            continue
        if not isinstance(path, Path):
            path = Path
        if path and path.exists() and path.is_file():
            path = path.expanduser().resolve()
            return path
    return None


def load_config_file(config_path) -> dict:
    with config_path.open("r") as config_fd:
        config_file_data = yaml.safe_load(config_fd)
        if not config_file_data:
            config_file_data = {}
        if not isinstance(config_file_data, dict):
            raise click.ClickException(
                f'error="Invalid configuration file format" path={config_path}. expected=dict revceived={type(config_file_data)}'
            )
    log.debug(f'event="Loaded configuration file data" path={config_path} data={config_file_data}')
    return config_file_data


def entrypoint():
    """Entrypoint for the MCP relay server."""
    setup_logging()
    try:
        cli()
    except TypeError as te:
        log.exception(f"event=cli_error error={te}")
        raise
    except McpRelayBaseError:
        return 1


if __name__ == "__main__":
    sys.exit(entrypoint())
