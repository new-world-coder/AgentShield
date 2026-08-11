# AgentShield Python SDK

Python-first runtime and Assure primitives for AgentShield.

## Scope (v0.1 — Phase 0 + Phase 1 start)

- **MCP firewall:** schema pin/hash, poisoning scan, tool allowlist
- **Assure:** action oracles, mutational payload packs, impact scoring, SARIF export

See `docs/STRATEGY.md` and `docs/threat-model.md` in the repo root.

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
agentshield mcp scan --tools examples/tools.json

# Expand base packs with mutations
agentshield packs expand --out /tmp/packs.json

# Evaluate an execution trace with action oracles
agentshield oracle evaluate --trace examples/trace.json

# Export findings to SARIF
agentshield sarif export --findings findings.json --out results.sarif
```

## Design notes

- Deterministic oracles are authoritative; regex/text matches are weak signals only.
- MCP pin hashes cover **name + description + input schema** (canonical JSON).
- Severity is impact-based (see threat model), not pattern-echo based.
