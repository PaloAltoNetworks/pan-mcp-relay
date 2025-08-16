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
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Any, Literal, TypedDict

from pydantic import AliasChoices, AliasGenerator, AliasPath, BaseModel, ConfigDict, Field, SecretStr
from pydantic.alias_generators import to_camel, to_pascal

from pan_aisecurity_mcp_relay.constants import (
    API_ENDPOINT_RE,
    DEFAULT_API_ENDPOINT,
    ENV_AI_PROFILE,
    ENV_API_ENDPOINT,
    ENV_API_KEY,
    MAX_MCP_SERVERS_DEFAULT,
    MAX_MCP_TOOLS_DEFAULT,
    TOOL_REGISTRY_CACHE_TTL_DEFAULT,
    TransportType,
)
from pan_aisecurity_mcp_relay.utils import expand_vars

log = logging.getLogger("pan-mcp-relay.config")


class MaskedValue(str):
    def __repr__(self):
        s = super().__repr__()
        if len(s) <= 7:
            return "*" * len(s)
        return "".join(["*" for c in s[:-7]]) + s[-7:-1]


class SecurityScannerEnv(TypedDict):
    ENV_API_KEY: str
    ENV_AI_PROFILE: str
    ENV_API_ENDPOINT: str


class CustomAliasGenerator(AliasGenerator):
    def generate_aliases(self, field_name: str) -> tuple[str | None, str | AliasPath | AliasChoices | None, str | None]:
        alias = field_name
        validation_aliases = make_validation_aliases(field_name)
        serialization_aliases = field_name
        return alias, validation_aliases, serialization_aliases


def make_validation_aliases(field_name: str, *extras: str) -> AliasChoices:
    choices = dict.fromkeys([
        field_name,
        to_camel(field_name),
        to_pascal(field_name),
        field_name.lower(),
        field_name.replace("_", "-"),
        field_name.replace("_", ""),
        *extras,
    ])
    return AliasChoices(*choices.keys())


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
    host: IPv4Address | IPv6Address = Field(default="127.0.0.1", description="Host for HTTP/SSE server")
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

    dotenv: str | Path | None = Field(default=".env", description="Path to .env file")
    show_config: bool = Field(default=False, description="Show configuration and exit")

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

    def security_scanner_env(self) -> SecurityScannerEnv:
        """Get environment variables for the Security Scanner."""
        return SecurityScannerEnv(**{
            ENV_API_KEY: str(self.api_key.get_secret_value()),
            ENV_AI_PROFILE: str(self.ai_profile),
            ENV_API_ENDPOINT: self.api_endpoint,
        })


class BaseMcpServer(BaseModel):
    pass


class StdioMcpServer(BaseMcpServer):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)
    type: Literal["stdio"] | None = "stdio"
    command: str
    args: list[str] | None = Field(default_factory=list)
    cwd: Path | None = None
    env: dict[str, str] | None = Field(default_factory=dict)


class SseMcpServer(BaseMcpServer):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)
    type: Literal["sse"] | None = "sse"
    url: str
    headers: dict[str, str] | None = None


class StreamableHttpMcpServer(BaseMcpServer):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)
    type: Literal["http"] | None = "http"
    url: str
    headers: dict[str, str] | None = Field(default_factory=dict)


type McpServerType = StdioMcpServer | SseMcpServer | StreamableHttpMcpServer


class Config(BaseModel):
    """Configuration for the MCP Relay."""

    model_config = ConfigDict(alias_generator=to_camel, extra="ignore", validate_by_alias=True, validate_by_name=True)

    mcp_relay: McpRelayConfig | None = Field(description="MCP Relay Configuration", alias="mcpRelay")
    mcp_servers: dict[str, StdioMcpServer | SseMcpServer | StreamableHttpMcpServer] | None = Field(
        default_factory=dict, description="MCP Servers Configuration", alias="mcpServers"
    )
