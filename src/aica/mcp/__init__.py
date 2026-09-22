"""MCP client support (MCP-001, MCP-007).

Servers are named in configuration and started as child processes; their tools are wrapped as
ordinary AICA tools so policy, argument validation, approval and audit apply unchanged. What
a server says is data - never authority.
"""

from aica.mcp.client import (
    CLIENT_NAME,
    PROTOCOL_VERSION,
    MCPClient,
    MCPError,
    RemoteTool,
    ServerInfo,
)
from aica.mcp.config import (
    DEFAULT_MCP_PATH,
    MCPConfig,
    MCPConfigError,
    ServerConfig,
    load_mcp_config,
)
from aica.mcp.protocol import (
    JsonRpcError,
    StdioTransport,
    Transport,
    TransportError,
    TransportTimeout,
)
from aica.mcp.schema import SchemaError, model_from_schema

__all__ = [
    "CLIENT_NAME",
    "DEFAULT_MCP_PATH",
    "PROTOCOL_VERSION",
    "JsonRpcError",
    "MCPClient",
    "MCPConfig",
    "MCPConfigError",
    "MCPError",
    "RemoteTool",
    "SchemaError",
    "ServerConfig",
    "ServerInfo",
    "StdioTransport",
    "Transport",
    "TransportError",
    "TransportTimeout",
    "load_mcp_config",
    "model_from_schema",
]
