# AgentShield Python SDK

Python-first runtime and Assure primitives for AgentShield.

## Scope (v0.1 — Phase 0 + Phase 1)

- **MCP firewall:** schema pin/hash, poisoning scan, tool allowlist, **adapter**, **pin registry**, **policy YAML**, **integrated audit**
- **AgentBOM:** inventory of agent + MCP tools/decisions
- **Assure:** action oracles, mutational payload packs, impact scoring, SARIF export
- **CI:** composite GitHub Action `.github/actions/mcp-audit`

See `docs/STRATEGY.md`, `docs/MCP_SECURITY.md`, and `docs/threat-model.md` in the repo root.

## Install

```bash
cd python
pip install -e ".[dev]"
```

## CLI

```bash
# Pin an MCP tool schema
agentshield mcp pin --tool examples/tool.json

# Scan tools for poisoning / typosquat / shadow names
agentshield mcp scan --tools examples/tools_poisoned.json

# Full security audit (scan + pins + policy) → JSON + SARIF
agentshield mcp audit \
  --tools examples/tools_poisoned.json \
  --policy examples/policy.yaml \
  --ignore-unpinned \
  --sarif /tmp/mcp.sarif \
  --fail-on-severity high

# Persistent pin registry
agentshield mcp pin-registry add --tools examples/tool.json --pins /tmp/pins.json
agentshield mcp pin-registry verify --tools examples/tool.json --pins /tmp/pins.json
agentshield mcp pin-registry list --pins /tmp/pins.json

# AgentBOM from an audit report
agentshield bom generate --audit-report /tmp/audit.json --out /tmp/agentbom.json

# Expand base packs with mutations
agentshield packs expand --out /tmp/packs.json

# Evaluate an execution trace with action oracles
agentshield oracle evaluate --trace examples/trace_fail.json

# Export findings to SARIF
agentshield sarif export --findings findings.json --out results.sarif
```

## Design notes

- Deterministic oracles are authoritative; regex/text matches are weak signals only.
- MCP pin hashes cover **name + description + input schema** (canonical JSON).
- Severity is impact-based (see threat model), not pattern-echo based.
- Fail-closed allowlists are the production default.
