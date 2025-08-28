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
import json
import logging
import os
import shutil
import signal
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Literal, TypeVarTuple

import anyio
import click
import click.shell_completion
import dotenv
import rich.logging
import yaml
from click.core import ParameterSource
from pydantic import ValidationError
from rich import print

from . import utils
from ._version import __version__
from .configuration import Config
from .constants import (
    ENV_AI_PROFILE,
    ENV_API_ENDPOINT,
    ENV_API_KEY,
    ENV_CONFIG_FILE,
    ENV_DOTENV,
    ENV_HOST,
    ENV_LOG_LEVEL,
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
from .exceptions import McpRelayBaseError, McpRelayConfigurationError
from .pan_security_relay import PanSecurityRelay
from .server import (
    run_http_server,
    run_stdio_server,
    setup_http_server,
    setup_sse_server,
)
from .utils import deep_merge, expand_path, expand_vars, getenv

log = utils.get_logger(__name__)

PosArgsT = TypeVarTuple("PosArgsT")


def setup_logging():
    """Initialize logging."""
    stderr = rich.console.Console(stderr=True)
    default_level = get_loglevel()
    logging.basicConfig(
        level=default_level,
        format="%(message)s",
        handlers=[
            rich.logging.RichHandler(
                log_time_format="%X",
                rich_tracebacks=True,
                console=stderr,
                enable_link_path=True,
            )
        ],
        force=True,
    )


def set_loglevels(**kwargs) -> None:
    """Configure Log Levels for libraries"""
    # level_to_name = getattr(logging, "_nameToLevel")  # int -> str
    log_level = get_loglevel(**kwargs)
    logging.getLogger().setLevel(log_level)
    if log_level >= logging.INFO:  # WARNING, ERROR, CRITICAL
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
    if log_level < logging.INFO:  # DEBUG, NOTSET
        logging.getLogger("httpcore").setLevel(logging.INFO)
        logging.getLogger("httpx").setLevel(logging.INFO)


def get_loglevel(**kwargs):
    kwarg_level = kwargs.get("log_level", None)
    if isinstance(kwarg_level, str):
        kwarg_level = kwarg_level.upper()
    env_level = os.getenv(ENV_LOG_LEVEL, None)
    if isinstance(env_level, str):
        env_level = env_level.upper()
    log_level = kwarg_level or env_level or logging.INFO
    name_to_level = getattr(logging, "_nameToLevel")  # str -> int
    if isinstance(log_level, str):
        if log_level in name_to_level:
            log_level = name_to_level[log_level]
        else:
            log.warning(f"Unknown logging level: {log_level}, using INFO instead.")
            log_level = logging.INFO
    return log_level


context_settings = dict(
    auto_envvar_prefix=RELAY_PREFIX,
    max_content_width=shutil.get_terminal_size().columns,
    show_default=True,
    help_option_names=["-h", "--help"],
)


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


@click.group(context_settings=context_settings, invoke_without_command=True)
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
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar=ENV_CONFIG_FILE,
    help=f"Path to configuration file (yaml, json) [{ENV_CONFIG_FILE}={getenv(ENV_CONFIG_FILE)}]",
)
@click.option(
    "transport",
    "-t",
    "--transport",
    type=click.Choice(TransportType._member_names_),
    default="stdio",
    help=f"Transport protocol to use [{ENV_TRANSPORT}={getenv(ENV_TRANSPORT)}]",
)
@click.option(
    "host", "-H", "--host", default="127.0.0.1", help=f"Host for HTTP/SSE server [{ENV_HOST}={getenv(ENV_HOST)}]"
)
@click.option(
    "port", "-p", "--port", type=int, default=8000, help=f"Port for HTTP/SSE server [{ENV_PORT}={getenv(ENV_PORT)}]"
)
@click.option(
    "tool_registry_cache_ttl",
    "-TTL",
    "--tool-registry-cache-ttl",
    type=int,
    default=TOOL_REGISTRY_CACHE_TTL_DEFAULT,
    help=f"Tool registry cache TTL (in seconds) [{ENV_TOOL_CACHE_TTL}={getenv(ENV_TOOL_CACHE_TTL)}]",
)
@click.option(
    "max_mcp_servers",
    "-MS",
    "--max-mcp-servers",
    type=int,
    default=MAX_MCP_SERVERS_DEFAULT,
    help=f"Maximum number of downstream MCP servers to allow [{ENV_MAX_SERVERS}={getenv(ENV_MAX_SERVERS)}]",
)
@click.option(
    "max_mcp_tools",
    "-MT",
    "--max-mcp-tools",
    type=int,
    default=MAX_MCP_TOOLS_DEFAULT,
    help=f"Maximum number of MCP tools to allow [{ENV_MAX_TOOLS}={getenv(ENV_MAX_TOOLS)}]",
)
@click.option(
    "dotenv",
    "--env",
    is_flag=False,
    flag_value=".env",
    envvar=ENV_DOTENV,
    help=(
        f"Use ./.env file, or specify colon separated path to .env file(s)"
        f"or directories containing .env files. [{ENV_DOTENV}={getenv(ENV_DOTENV)}]"
    ),
)
@click.option("use_system_ca", "--system-ca", is_flag=True, help="Use System CA instead of Mozilla CA Bundle")
@click.option(
    "custom_ca_file",
    "--capath",
    type=click.types.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to Custom Trusted CA bundle",
)
@click.option(
    "log_level",
    "--debug",
    "-d",
    is_flag=True,
    flag_value="debug",
    help="Extremely verbose logging output (DEBUG)",
)
@click.option(
    "log_level", "--verbose", "-v", is_flag=True, flag_value="info", help="Verbose logging output (INFO, DEFAULT)"
)
@click.option("log_level", "--quiet", "-q", is_flag=True, flag_value="warning", help="Minimal logging output (WARNING)")
@click.option(
    "show_config",
    "--show-config",
    "--dump-config",
    envvar=ENV_SHOW_CONFIG,
    is_flag=True,
    help=f"Show configuration and exit [{ENV_SHOW_CONFIG}={getenv(ENV_SHOW_CONFIG)}]",
)
@click.version_option(__version__, *("--version", "-V"), message="%(version)s")
@click.pass_context
def cli(ctx, **kwargs) -> int:
    """Run the MCP Relay Server."""
    ctx.ensure_object(dict)
    dotenv_search = kwargs.get("dotenv") or ".env"
    dotenv_src = ctx.get_parameter_source("dotenv")

    set_loglevels(**kwargs)
    if (log_level := kwargs.get("log_level", None)) and isinstance(log_level, str):
        kwargs["log_level"] = logging.getLevelName(log_level.upper())

    try:
        load_dotenvs(dotenv_search=dotenv_search, dotenv_src=dotenv_src)
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

    ctx.obj["config"] = config
    if ctx.invoked_subcommand is None:
        ctx.invoke(run_server)
    return 0


@cli.command(name="run")
@click.pass_context
def run_server(ctx: click.Context) -> int:
    """Run the MCP Relay Server."""
    config = ctx.obj["config"]
    # start = functools.partial(start_mcp_relay_server, config=config)
    # return anyio.run(start, backend="asyncio")
    return asyncio.run(start_mcp_relay_server(config=config))


@cli.command(name="show-config")
@click.option("include_api_key", "--include-api-key", is_flag=True, help="Include API key in output")
@click.pass_context
def show_config(ctx: click.Context, include_api_key: bool) -> int:
    """Print MCP Relay Configuration and exit."""
    config: Config = ctx.obj["config"]
    log.info("event=show_config")
    dict_config = config.model_dump(
        mode="json",
        exclude_unset=False,
        exclude_none=False,
        by_alias=True,
    )
    if include_api_key:
        dict_config["mcpRelay"]["api_key"] = config.mcp_relay.api_key.get_secret_value()
    print(yaml.dump(dict_config, sort_keys=False, indent=2))
    return 0


@cli.command(name="json-schema")
@click.option(
    "output",
    "-o",
    "--output",
    default=None,
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    help="Path to write JSON Schema to",
)
@click.option(
    "format", "-f", "--format", type=click.Choice(choices=["json", "yaml"]), default="json", help="Schema Output Format"
)
@click.pass_context
def json_schema(ctx: click.Context, output: Path, format: Literal["yaml"] | Literal["json"] = "json") -> int:
    """Print Configuration File JSON Schema, optionally to a file."""
    schema = Config.model_json_schema(by_alias=True)
    if format == "yaml":
        schema_text = yaml.safe_dump(schema)
    elif format == "json":
        schema_text = json.dumps(schema, indent=2, sort_keys=False, default=str)
    if output:
        if output.is_char_device():
            pass
        elif output.exists() and output.is_file():
            confirmed = click.confirm(
                f"output file {output} already exists, would you like to overwrite it?", default=True
            )
            if not confirmed:
                click.echo("Aborting.")
                return 1
        output.write_text(schema_text)
    else:
        print(schema_text, file=sys.stdout)
    return 0


@cli.command(name="completion")
@click.argument(
    "shell",
    required=True,
    type=click.types.Choice(
        choices=[
            "zsh",
            "bash",
            "fish",
        ]
    ),
)
@click.pass_context
def completion(ctx: click.Context, shell: str):
    """
    Generate shell autocompletion script for the specified shell.
    """
    root = ctx.find_root()
    complete_var = "_PAN_MCP_RELAY_COMPLETE"
    return click.shell_completion.shell_complete(root.command, {}, root.info_name, complete_var, "zsh_source")


async def signal_handler(scope: anyio.CancelScope):
    with anyio.open_signal_receiver(signal.SIGINT, signal.SIGTERM, signal.SIGABRT, signal.SIGQUIT) as signals:
        async for signum in signals:
            signame = str(signum).split(".")[-1]
            log.warning(f"Received signal {signame}")

            scope.cancel()
            return


async def start_mcp_relay_server(config: Config):
    """Initialize and Start the MCP Relay"""
    mcp_servers_config = {k: v.model_dump() for k, v in config.mcp_servers.items()}
    relay_config = config.mcp_relay

    try:
        relay_server = PanSecurityRelay(
            config=relay_config,
            mcp_servers_config=mcp_servers_config,
        )
    except McpRelayConfigurationError as ce:
        log.error(f"Failed to instantiate MCP Relay server: {ce}")
        return 1

    async with anyio.create_task_group() as tg:
        tg.start_soon(signal_handler, tg.cancel_scope)
        async with relay_server:
            # Create and run the MCP server
            app = await relay_server.mcp_server()
            func: Callable[[*PosArgsT], Awaitable[Any]]
            args: tuple[*PosArgsT] = ()
            match relay_config.transport:
                case TransportType.stdio:
                    func, args = run_stdio_server, (config.mcp_relay, app)
                case TransportType.sse:
                    sse_server = setup_sse_server(config.mcp_relay, app, relay_server.server_lifespan)
                    func, args = run_http_server, (config.mcp_relay, sse_server)
                case TransportType.http:
                    shttp_server = setup_http_server(config.mcp_relay, app, relay_server.server_lifespan)
                    func, args = run_http_server, (config.mcp_relay, shttp_server)
                case _:
                    log.error(f"Invalid transport type: {relay_config.transport}")
                    return 1
            async with anyio.create_task_group() as runner_tg:
                runner_tg.start_soon(func, *args)

    return 0


def load_dotenvs(dotenv_search: str | None, dotenv_src: ParameterSource):
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
    if not loaded_paths and dotenv_src in [ParameterSource.COMMANDLINE, ParameterSource.ENVIRONMENT]:
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


if __name__ == "__main__":
    sys.exit(entrypoint())
