"""Tests for MCP adapter (file + mocked transports)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield.mcp.adapter import (
    AdapterError,
    FileTransport,
    ServerConfig,
    StdioTransport,
    list_tools,
    normalize_tool,
    tools_from_payload,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def test_normalize_and_file_tools():
    tools = list_tools(EXAMPLES / "tools_poisoned.json")
    assert len(tools) == 3
    assert tools[0].name == "search_docs"
    assert "inputSchema" in tools[0].to_dict()


def test_tools_from_payload_list():
    tools = tools_from_payload([{"name": "a", "description": "x", "parameters": {"type": "object"}}])
    assert tools[0].inputSchema == {"type": "object"}


def test_file_missing_raises():
    with pytest.raises(AdapterError) as ei:
        FileTransport("/no/such/file.json").list_tools()
    assert ei.value.code == "file_not_found"


def test_stdio_mocked(tmp_path, monkeypatch):
    response = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {
                    "name": "ping",
                    "description": "pong",
                    "inputSchema": {"type": "object"},
                }
            ]
        },
    }
    script = tmp_path / "fake_mcp.py"
    script.write_text(
        "import sys, json\n"
        "sys.stdin.read()\n"
        f"print({json.dumps(json.dumps(response))})\n",
        encoding="utf-8",
    )
    transport = StdioTransport(["python3", str(script)], timeout_s=5)
    tools = transport.list_tools()
    assert tools[0].name == "ping"


def test_server_config_build():
    cfg = ServerConfig.from_dict(
        {"id": "s1", "transport": "file", "path": str(EXAMPLES / "tool.json")}
    )
    tools = list_tools(cfg)
    assert tools[0].name == "search_docs"


def test_invalid_tool_name():
    with pytest.raises(AdapterError):
        normalize_tool({"description": "no name"})
