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
import logging
import urllib.parse
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    AliasChoices,
    AliasGenerator,
    AliasPath,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    SecretStr,
    model_validator,
)
from pydantic.alias_generators import to_camel, to_pascal
from pydantic.types import PathType

from .constants import (
    API_ENDPOINT_RE,
    DEFAULT_API_ENDPOINT,
    MAX_MCP_SERVERS_DEFAULT,
    MAX_MCP_TOOLS_DEFAULT,
    TOOL_REGISTRY_CACHE_TTL_DEFAULT,
    TransportType,
)
from .exceptions import McpRelayConfigurationError
from .utils import expand_vars, get_logger

log = get_logger(__name__)


class CustomAliasGenerator(AliasGenerator):
    def generate_aliases(self, field_name: str) -> tuple[str | None, str | AliasPath | AliasChoices | None, str | None]:
        alias = field_name
        validation_aliases = make_validation_aliases(field_name)
        serialization_aliases = field_name
        return alias, validation_aliases, serialization_aliases


def make_validation_aliases(field_name: str, *extras: str) -> AliasChoices:
    field_names: list[str] = [field_name, *extras]
    choices: list[str] = []
    for field_name in field_names:
        for choice in (
            field_name,
            to_camel(field_name),
            to_pascal(field_name),
            field_name.lower(),
            field_name.replace("_", "-"),
            field_name.replace("_", ""),
        ):
            if choice not in choices:
                choices.append(choice)
    return AliasChoices(*choices)


class McpRelayConfig(BaseModel):
    """Configuration for the MCP Relay."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        validate_default=True,
        alias_generator=CustomAliasGenerator(),
    )

    api_key: SecretStr | None = Field(
        default=None,
        description="Prisma AIRS API Key",
        min_length=1,
        max_length=200,
        repr=False,
        exclude=False,
    )
    ai_profile: str | None = Field(
        default=None,
        description="Prisma AIRS AI Profile Name or ID",
    )
    api_endpoint: str | None = Field(
        default=DEFAULT_API_ENDPOINT,
        description="Prisma AIRS API Endpoint",
        pattern=API_ENDPOINT_RE,
        validation_alias=make_validation_aliases("api_endpoint", "endpoint"),
    )

    config_file: Path | None = Field(
        default=None,
        description="Path to configuration file",
        validation_alias=make_validation_aliases("config_file", "config_path"),
    )
    transport: TransportType = Field(default=TransportType.stdio, description="Transport protocol to use")
    host: IPvAnyAddress = Field(default="127.0.0.1", description="Host for HTTP/SSE server")
    port: int = Field(default=8000, description="Port for HTTP/SSE server", gt=0, lt=65535)
    tool_registry_cache_ttl: int = Field(
        default=TOOL_REGISTRY_CACHE_TTL_DEFAULT,
        description="Tool registry cache expiration time (in seconds)",
        gt=30,
    )
    max_mcp_servers: int = Field(
        default=MAX_MCP_SERVERS_DEFAULT, description="Maximum number of MCP servers to allow", gt=0
    )
    max_mcp_tools: int = Field(default=MAX_MCP_TOOLS_DEFAULT, description="Maximum number of MCP tools to allow", gt=0)

    dotenv: Path | None = Field(default=".env", description="Path to .env file")
    show_config: bool = Field(default=False, description="Show configuration and exit")
    log_level: int | None = Field(default=logging.DEBUG, description="Logging level")
    use_system_ca: bool = Field(default=False, description="Use system CA")
    custom_ca_file: Annotated[Path, PathType("file")] | None = Field(
        default=None, description="Path to custom trusted root CA file"
    )

    def log_level_name(self) -> str:
        """Log level name. One of: NOTSET, DEBUG, INFO, WARNING, ERROR, CRITICAL."""
        return logging.getLevelName(self.log_level)

    def debug_enabled(self) -> bool:
        return self.log_level <= logging.DEBUG

    def model_post_init(self, context: Any):
        log.debug(f"Expanding environment variables on {self!r}")
        for k in self.__class__.model_fields.keys():
            v = getattr(self, k)
            if isinstance(v, SecretStr):
                v = v.get_secret_value()
            if not isinstance(v, str):
                continue
            v = v.strip()
            new_v = expand_vars(v).strip()
            if new_v != v:
                log.debug(f"Expanded env var {k!r} from {v!r} to {new_v!r}")
                setattr(self, k, new_v)


class BaseMcpServer(BaseModel):
    """Base Class for all MCP Servers"""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)
    type: TransportType | None


class StdioMcpServer(BaseMcpServer):
    """Stdio MCP Server"""

    type: Literal[TransportType.stdio] = Field(default=TransportType.stdio)
    command: str
    args: list[str] | None = Field(default_factory=list)
    cwd: Path | None = None
    env: dict[str, str] | None = Field(default_factory=dict)

    def model_post_init(self, context: Any):
        if self.type is None:
            self.type = TransportType.stdio


class HttpMcpServerBase(BaseMcpServer):
    """Base class for HTTP MCP Servers (SSE, Streamable HTTP)"""

    type: Literal[TransportType.sse, TransportType.http] | None
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: float = Field(default=30.0, ge=0, lt=300)
    sse_read_timeout: float = Field(default=30.0, ge=0, lt=300)

    @model_validator(mode="before")
    @classmethod
    def set_type_if_missing(cls, data: Any) -> Any:
        if isinstance(data, dict):
            urlvar: str | Any | None = data.get("url", None)
            type_: str | Any | None = data.get("type", None)
            if isinstance(type_, str) and not type_.strip():
                type_ = None
            if not isinstance(urlvar, str):
                return data

            url = urllib.parse.urlparse(urlvar)
            if type_ is None:
                if "sse" in url.path.lower():
                    type_ = TransportType.sse
                else:
                    type_ = TransportType.http
                data["type"] = str(type_)
        return data

    def model_post_init(self, context: Any):
        self.url = self.url.strip()
        headers = self.headers.copy()
        self.headers = {}
        for k, v in headers.items():
            k = k.strip()
            self.headers[k] = v.strip()

        url = urllib.parse.urlparse(self.url)
        if self.type is None:
            if "sse" in url.path.lower():
                self.type = TransportType.sse
            else:
                self.type = TransportType.http


class SseMcpServer(HttpMcpServerBase):
    """SSE MCP Server"""

    type: Literal[TransportType.sse] = Field(default=TransportType.sse)


class HttpMcpServer(HttpMcpServerBase):
    """Streamable HTTP MCP Server"""

    type: Literal[TransportType.http] = Field(default=TransportType.http)
    terminate_on_close: bool = False


type McpServerType = StdioMcpServer | HttpMcpServer | SseMcpServer


class Config(BaseModel):
    """Configuration for the MCP Relay."""

    model_config = ConfigDict(alias_generator=to_camel, extra="ignore", validate_by_alias=True, validate_by_name=True)

    mcp_relay: McpRelayConfig | None = Field(
        default_factory=McpRelayConfig, description="MCP Relay Configuration", alias="mcpRelay"
    )
    mcp_servers: dict[str, StdioMcpServer | HttpMcpServer | SseMcpServer] | None = Field(
        default_factory=dict,
        description="MCP Servers Configuration",
        alias="mcpServers",
        min_length=1,
    )

    def model_post_init(self, context: Any, /) -> None:
        if self.mcp_servers and len(self.mcp_servers) > self.mcp_relay.max_mcp_servers:
            raise McpRelayConfigurationError(
                f"Too many MCP servers ({len(self.mcp_servers)} > {self.mcp_relay.max_mcp_servers})"
            )

    # @field_validator("mcp_servers", mode="before")
    # @classmethod
    # def server_type(cls, value: dict[str, McpServerType] | Any) -> Any:
    #     if isinstance(value, HttpMcpServerBase):
    #         if isinstance(value, HttpMcpServer):
    #             return value
    #         if isinstance(value, SseMcpServer):
    #             return value
    #     if isinstance(value, dict):
    #         typ = value.get("type")
    #         if typ is not None and typ not in [
    #             str(TransportType.stdio),
    #             str(TransportType.sse),
    #             str(TransportType.http),
    #         ]:
    #             raise ValueError(f"invalid transport type: {typ}")
    #     return value
