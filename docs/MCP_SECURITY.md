# MCP Security — Phase 1

AgentShield’s MCP & Tool Firewall turns tool inventories into a **fail-closed security gate**: pin schemas, scan for poisoning, detect rug pulls, enforce allowlists, export SARIF, and emit an AgentBOM.

## Quick start (CLI)

```bash
cd python
pip install -e ".[dev]"

# Full audit (scan + pin verify + policy)
agentshield mcp audit \
  --tools examples/tools_poisoned.json \
  --policy examples/policy.yaml \
  --ignore-unpinned \
  --sarif /tmp/mcp.sarif \
  --fail-on-severity high

# Pin registry
agentshield mcp pin-registry add --tools examples/tool.json --pins /tmp/pins.json
agentshield mcp pin-registry verify --tools examples/tool.json --pins /tmp/pins.json

# AgentBOM
agentshield mcp audit --tools examples/tool.json --policy examples/policy.yaml --ignore-unpinned --out /tmp/audit.json
agentshield bom generate --audit-report /tmp/audit.json --out /tmp/agentbom.json
```

## Policy file

```yaml
fail_closed: true
allowed_tools:
  - search_docs
  - read_file
approval_required:
  - write_file
  - send_email
blocked_patterns:
  - "^exec_"
```

- `fail_closed: true` (default) denies tools not explicitly allowed or marked for approval.
- `require_approval` is recorded as a **High** finding in Phase 1 (no human UX yet).
- Override via env: `AGENTSHIELD_POLICY_FILE`, `AGENTSHIELD_ALLOWED_TOOLS`, `AGENTSHIELD_APPROVAL_REQUIRED`, `AGENTSHIELD_FAIL_CLOSED`.

## Pinning & rug-pull detection

Pins hash canonical `name + description + inputSchema` (SHA-256).

1. Approve tools → `mcp pin-registry add`
2. On reconnect / CI → `mcp pin-registry verify` or `mcp audit`
3. Description or schema drift → `schema_drift` / Critical finding (MCP02)

Default registry path: `.agentshield/pins.json` (or `AGENTSHIELD_PINS_FILE`).

## Adapter transports

| Transport | Config |
|-----------|--------|
| `file` | `{ "transport": "file", "path": "tools.json" }` |
| `stdio` | `{ "transport": "stdio", "command": ["python", "server.py"] }` |
| `sse` / `http` | `{ "transport": "http", "url": "https://…/mcp" }` |

Errors are structured (`AdapterError`) — never a silent empty success.

## CI (GitHub Action)

```yaml
- uses: ./.github/actions/mcp-audit
  with:
    tools-file: path/to/tools.json
    policy-file: path/to/policy.yaml
    pins-file: path/to/pins.json   # optional
    fail-on-severity: high
    sarif-output: mcp-audit.sarif
```

Example workflow: `.github/workflows/mcp-audit-example.yml` (`workflow_dispatch`).

## API

JWT-protected routes (see `docs/API.md`):

- `POST /api/mcp/audit`
- `POST /api/mcp/pin`
- `POST /api/mcp/verify`
- `GET /api/mcp/pins`
- `POST /api/mcp/sarif`
- `POST /api/mcp/bom`

## Threat coverage (Phase 1)

| Control | MCP Top 10 |
|---------|------------|
| Description poisoning scan | MCP01 / MCP03 |
| Schema pin + drift | MCP02 |
| Typosquat / shadow tools | MCP03 / MCP08 |
| Allowlist / approval gate | MCP05 |
| SARIF + AgentBOM | Govern / supply-chain evidence |

Human-in-the-loop approval UI, CEL/Rego policy DSL, and runtime IFC are **Phase 2** (see `docs/PHASE1_GAPS.md`).
