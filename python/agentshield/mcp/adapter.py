"""MCP adapter — list tools from file, stdio, or SSE/HTTP transports.

Phase 1: normalized ToolDefinition extraction for pin/scan/firewall.
Does not require the official MCP SDK; uses a minimal JSON-RPC client.
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence


class AdapterError(Exception):
    """Structured adapter failure (never a silent empty success)."""

    def __init__(self, message: str, *, code: str = "adapter_error") -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass
class ToolDefinition:
    name: str
    description: str = ""
    inputSchema: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.inputSchema,
        }


def normalize_tool(raw: Mapping[str, Any]) -> ToolDefinition:
    """Normalize MCP / OpenAI-style tool objects into ToolDefinition."""
    name = str(raw.get("name") or "").strip()
    if not name:
        raise AdapterError("Tool missing name", code="invalid_tool")
    description = str(raw.get("description") or "")
    schema = (
        raw.get("inputSchema")
        or raw.get("input_schema")
        or raw.get("parameters")
        or {}
    )
    if not isinstance(schema, dict):
        schema = {}
    return ToolDefinition(name=name, description=description, inputSchema=schema)


def tools_from_payload(payload: Any) -> list[ToolDefinition]:
    """Accept a list, a single tool object, or `{ \"tools\": [...] }`."""
    if isinstance(payload, list):
        raw_tools = payload
    elif isinstance(payload, Mapping):
        if "tools" in payload:
            raw_tools = payload.get("tools")
            if not isinstance(raw_tools, list):
                raise AdapterError("'tools' must be a list", code="invalid_payload")
        elif payload.get("name"):
            raw_tools = [payload]
        else:
            raise AdapterError(
                "Payload must be a list, a tool object, or object with 'tools' key",
                code="invalid_payload",
            )
    else:
        raise AdapterError("Unsupported tools payload type", code="invalid_payload")

    return [normalize_tool(t) for t in raw_tools if isinstance(t, Mapping)]


def load_tools_file(path: str | Path) -> list[ToolDefinition]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return tools_from_payload(data)


class Transport(ABC):
    @abstractmethod
    def list_tools(self) -> list[ToolDefinition]:
        raise NotImplementedError


class FileTransport(Transport):
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def list_tools(self) -> list[ToolDefinition]:
        if not self.path.exists():
            raise AdapterError(
                f"Tools file not found: {self.path}", code="file_not_found"
            )
        try:
            return load_tools_file(self.path)
        except AdapterError:
            raise
        except json.JSONDecodeError as exc:
            raise AdapterError(f"Invalid JSON: {exc}", code="invalid_json") from exc


class StdioTransport(Transport):
    """Minimal MCP stdio JSON-RPC client (tools/list)."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        timeout_s: float = 15.0,
        cwd: str | None = None,
    ) -> None:
        if not command:
            raise AdapterError("stdio command required", code="invalid_config")
        self.command = list(command)
        self.env = dict(env) if env else None
        self.timeout_s = timeout_s
        self.cwd = cwd

    def list_tools(self) -> list[ToolDefinition]:
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }
        payload = json.dumps(request) + "\n"
        try:
            proc = subprocess.run(
                self.command,
                input=payload.encode("utf-8"),
                capture_output=True,
                timeout=self.timeout_s,
                env=self.env,
                cwd=self.cwd,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterError(
                f"stdio MCP timeout after {self.timeout_s}s", code="timeout"
            ) from exc
        except FileNotFoundError as exc:
            raise AdapterError(
                f"stdio command not found: {self.command[0]}", code="command_not_found"
            ) from exc

        if proc.returncode != 0 and not proc.stdout:
            err = (proc.stderr or b"").decode("utf-8", errors="replace")[:500]
            raise AdapterError(
                f"stdio MCP exited {proc.returncode}: {err or 'no output'}",
                code="stdio_failed",
            )

        text = proc.stdout.decode("utf-8", errors="replace").strip()
        if not text:
            raise AdapterError("stdio MCP returned empty response", code="empty_response")

        # Take last non-empty JSON line (servers may emit logs)
        last_line = [ln for ln in text.splitlines() if ln.strip()][-1]
        try:
            response = json.loads(last_line)
        except json.JSONDecodeError as exc:
            raise AdapterError(
                f"stdio MCP non-JSON response: {last_line[:200]}",
                code="invalid_json",
            ) from exc

        if "error" in response:
            raise AdapterError(
                f"MCP error: {response['error']}", code="rpc_error"
            )
        result = response.get("result") or {}
        tools = result.get("tools") if isinstance(result, Mapping) else None
        if tools is None:
            raise AdapterError(
                "tools/list response missing result.tools", code="invalid_response"
            )
        return [normalize_tool(t) for t in tools if isinstance(t, Mapping)]


class SseHttpTransport(Transport):
    """Minimal HTTP JSON-RPC client for MCP SSE/HTTP endpoints."""

    def __init__(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_s: float = 15.0,
    ) -> None:
        if not url:
            raise AdapterError("SSE/HTTP url required", code="invalid_config")
        self.url = url
        self.headers = dict(headers or {})
        self.timeout_s = timeout_s

    def list_tools(self) -> list[ToolDefinition]:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                **self.headers,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raise AdapterError(
                f"HTTP MCP error {exc.code}", code="http_error"
            ) from exc
        except urllib.error.URLError as exc:
            raise AdapterError(
                f"HTTP MCP connection failed: {exc.reason}", code="connection_failed"
            ) from exc
        except TimeoutError as exc:
            raise AdapterError(
                f"HTTP MCP timeout after {self.timeout_s}s", code="timeout"
            ) from exc

        # SSE: extract data: lines; otherwise treat as JSON
        payload_text = raw.strip()
        if "data:" in payload_text and not payload_text.lstrip().startswith("{"):
            chunks: list[str] = []
            for line in payload_text.splitlines():
                if line.startswith("data:"):
                    chunks.append(line[5:].strip())
            payload_text = "\n".join(chunks).strip() or payload_text

        try:
            response = json.loads(payload_text.splitlines()[-1])
        except json.JSONDecodeError as exc:
            raise AdapterError(
                f"HTTP MCP non-JSON response: {payload_text[:200]}",
                code="invalid_json",
            ) from exc

        if "error" in response:
            raise AdapterError(f"MCP error: {response['error']}", code="rpc_error")
        result = response.get("result") or {}
        tools = result.get("tools") if isinstance(result, Mapping) else None
        if tools is None:
            raise AdapterError(
                "tools/list response missing result.tools", code="invalid_response"
            )
        return [normalize_tool(t) for t in tools if isinstance(t, Mapping)]


@dataclass
class ServerConfig:
    """Declarative MCP server config for list_tools."""

    id: str = "default"
    transport: str = "file"  # file | stdio | sse | http
    path: str | None = None
    command: list[str] | None = None
    url: str | None = None
    headers: dict[str, str] | None = None
    env: dict[str, str] | None = None
    timeout_s: float = 15.0

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ServerConfig":
        return cls(
            id=str(data.get("id") or data.get("server_id") or "default"),
            transport=str(data.get("transport") or "file").lower(),
            path=data.get("path") or data.get("tools_file"),
            command=list(data["command"]) if data.get("command") else None,
            url=data.get("url"),
            headers=dict(data["headers"]) if data.get("headers") else None,
            env=dict(data["env"]) if data.get("env") else None,
            timeout_s=float(data.get("timeout_s") or data.get("timeout") or 15.0),
        )


def build_transport(config: ServerConfig | Mapping[str, Any]) -> Transport:
    cfg = config if isinstance(config, ServerConfig) else ServerConfig.from_dict(config)
    kind = cfg.transport
    if kind == "file":
        if not cfg.path:
            raise AdapterError("file transport requires path", code="invalid_config")
        return FileTransport(cfg.path)
    if kind == "stdio":
        if not cfg.command:
            raise AdapterError("stdio transport requires command", code="invalid_config")
        return StdioTransport(cfg.command, env=cfg.env, timeout_s=cfg.timeout_s)
    if kind in ("sse", "http"):
        if not cfg.url:
            raise AdapterError(f"{kind} transport requires url", code="invalid_config")
        return SseHttpTransport(cfg.url, headers=cfg.headers, timeout_s=cfg.timeout_s)
    raise AdapterError(f"Unknown transport: {kind}", code="invalid_config")


def list_tools(server_config: ServerConfig | Mapping[str, Any] | str | Path) -> list[ToolDefinition]:
    """
    List and normalize tools from a server config or tools file path.

    Raises AdapterError on failure — never returns empty on error.
    """
    if isinstance(server_config, (str, Path)):
        tools = FileTransport(server_config).list_tools()
    else:
        tools = build_transport(server_config).list_tools()
    # Empty list is allowed only when the server truly has zero tools
    return tools
