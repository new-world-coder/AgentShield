# Phase 1 Handoff Brief — MCP & Tool Firewall (Full Implementation)

**Audience:** Coding agent implementing Phase 1  
**Base branch:** `main` (includes merged PR #2: Phase 0 + MCP primitives)  
**Target branch:** `cursor/phase1-mcp-firewall-f5d6`  
**Status:** Ready to implement  
**Last updated:** 2026-08-11

---

## Mission

Complete **Phase 1 — MCP & Tool Firewall** by turning existing Python/Node **primitives** into a **production-ready, integrated product surface**: live MCP inspection, persistent pinning, poisoning scans, allowlist enforcement, AgentBOM export, and a CI action.

Phase 0 (merged) delivered libraries and CLI stubs. Phase 1 delivers **wiring, persistence, API, CI, and docs** — not a rewrite of primitives unless bugs are found.

---

## What already exists (do NOT re-implement)

Merged in PR #2 (`318af9c` / `cursor/phase0-mcp-firewall-f5d6`):

| Area | Location | Notes |
|------|----------|-------|
| Schema pin/hash | `python/agentshield/mcp/pin.py` | Canonical JSON + SHA-256 pin records |
| Poisoning scanner | `python/agentshield/mcp/scan.py` | Typosquat, shadow-tool, description poisoning hooks |
| Tool allowlist | `python/agentshield/mcp/firewall.py` | `allow` / `deny` / `require_approval`, fail-closed |
| Assure oracles | `python/agentshield/assure/oracles.py` | Action-oracle evaluation (authoritative over regex) |
| Payload packs | `python/agentshield/assure/packs.py`, `python/agentshield/packs/base_packs.json` | Versioned mutational packs |
| SARIF | `python/agentshield/assure/sarif.py`, `server/services/assure/sarif.js` | Finding → SARIF 2.1.0 |
| Impact scoring | `python/agentshield/assure/scoring.py`, `server/services/assure/scoring.js` | Severity from impact, not echo |
| CLI | `python/agentshield/cli.py` | `mcp pin`, `mcp scan`, `mcp firewall`, oracle/pack helpers |
| Node Assure mirror | `server/services/assure/*` | JS oracles/packs/sarif/scoring for API layer |
| Threat model | `docs/threat-model.md` | OWASP LLM + Agentic + MCP Top 10 |
| Strategy | `docs/STRATEGY.md` | Roadmap and architecture |

**Reuse these modules.** Extend only where integration requires it.

---

## Phase 1 deliverables (must ship)

### D1 — MCP adapter (live + file-based)

Connect to MCP servers and normalize tool definitions for pin/scan/firewall.

**Requirements:**

- Support **stdio** and **SSE/HTTP** MCP transports (use official MCP Python SDK if available; otherwise minimal JSON-RPC client with clear transport interface).
- Implement `list_tools(server_config) -> ToolDefinition[]` with normalized shape:
  ```json
  {
    "name": "string",
    "description": "string",
    "inputSchema": { "type": "object", ... }
  }
  ```
- Support **file-based** input for offline/CI: JSON array or `{ "tools": [...] }` (already used by CLI examples in `python/examples/`).
- Timeouts, connection errors → structured error (no silent empty success).
- Unit tests with mocked transport + fixtures (`python/examples/tools_poisoned.json`).

**Suggested path:** `python/agentshield/mcp/adapter.py` (+ tests).

---

### D2 — Pin registry & rug-pull drift detection

Persist approved tool pins and detect schema drift on reconnect.

**Requirements:**

- Store pin records: `{ server_id, tool_name, pin_hash, pinned_at, algorithm, canonical_snapshot }`.
- On `tools/list`, re-hash each tool; compare to stored pin → emit finding:
  - `rug_pull` / `schema_drift` with severity **Critical**.
- Default storage: **JSON file** (`~/.agentshield/pins.json` or project-local `.agentshield/pins.json`) for v1; optional Mongo model if server integration needs it.
- API to: pin all tools from a server, verify all, list drift events.
- CLI subcommands: `agentshield mcp pin-registry add|verify|list` (extend existing CLI).

**Suggested paths:**

- `python/agentshield/mcp/registry.py`
- `server/models/McpPinRegistry.js` (if server-backed)
- `server/services/mcp/pinRegistry.js`

---

### D3 — Integrated MCP security scan pipeline

Single entrypoint that runs: **adapter → scan → pin verify → allowlist check**.

**Requirements:**

- `run_mcp_security_audit(config) -> AuditReport` containing:
  - `scan_findings[]` (poisoning, typosquat, shadow)
  - `drift_findings[]` (rug pull)
  - `firewall_decisions[]` (deny/approval for each tool)
  - `score`, `severity`, `summary`
- Map findings to shared `Finding` type (`python/agentshield/assure/scoring.py`).
- Export report as JSON and SARIF (`findings_to_sarif`).
- Wire into CLI: `agentshield mcp audit --server <config> --policy <yaml>`.

**Suggested path:** `python/agentshield/mcp/audit.py`.

---

### D4 — Tool allowlist & approval policy (config-driven)

Move from primitive to **policy file** usable in CLI, server, and CI.

**Requirements:**

- Policy schema (YAML or JSON):
  ```yaml
  fail_closed: true
  allowed_tools: [read_file, search]
  approval_required: [write_file, send_email, exec]
  blocked_patterns: []  # optional tool name regex
  ```
- Load policy from file + env override.
- `require_approval` must appear in audit report (not silently skipped).
- Human approval is **out of scope** for Phase 1 — record `REQUIRE_APPROVAL` as finding with severity High; UX is Phase 1.5 or Phase 2.

**Suggested path:** `python/agentshield/mcp/policy.py`.

---

### D5 — Server API routes (Node)

Expose MCP audit to the existing Express API (JWT-protected).

**Requirements:**

| Method | Route | Purpose |
|--------|-------|---------|
| POST | `/api/mcp/audit` | Run audit on tools JSON or server config |
| POST | `/api/mcp/pin` | Pin tools; return pin records |
| POST | `/api/mcp/verify` | Verify pins; return drift findings |
| GET | `/api/mcp/pins` | List stored pins (scoped to user/org) |
| POST | `/api/mcp/sarif` | Audit → SARIF (or reuse `/api/results/sarif` with normalized findings) |

- Invoke Python via **subprocess** (`python -m agentshield.cli ...`) OR port audit orchestration to Node using `server/services/assure/*` + new `server/services/mcp/*`. **Prefer subprocess for scan/pin parity** unless you port with identical test vectors.
- Validate inputs with Joi; never log secrets (MCP env vars, tokens).
- Add integration tests in `server/tests/mcp.audit.test.js`.

**Suggested paths:**

- `server/routes/mcp.js`
- `server/services/mcp/runAudit.js`

Register in `server/index.js`.

---

### D6 — AgentBOM generator

Inventory agent + MCP attack surface as a machine-readable BOM.

**Requirements:**

- AgentBOM v1 JSON schema:
  ```json
  {
    "bomVersion": "1.0",
    "agentShieldVersion": "...",
    "generatedAt": "ISO-8601",
    "agent": { "name", "adapter", "model" },
    "mcpServers": [{ "id", "transport", "tools": [{ "name", "pinHash", "decision" }] }],
    "policies": [{ "name", "path", "hash" }],
    "findingsSummary": { "critical", "high", "medium", "low" }
  }
  ```
- CLI: `agentshield bom generate --audit-report <json> --out agentbom.json`
- API: `GET /api/mcp/bom/:auditId` or include in audit response.
- CycloneDX mapping is **optional stretch** — document as follow-up in GAPS file if deferred.

**Suggested path:** `python/agentshield/bom/agentbom.py`.

---

### D7 — GitHub Action (CI gate)

Publish a composite action that fails PRs on MCP security regressions.

**Requirements:**

- Path: `.github/actions/mcp-audit/action.yml`
- Inputs:
  - `tools-file` (required for v1)
  - `policy-file`
  - `pins-file` (optional baseline)
  - `fail-on-severity` (default: `high`)
  - `sarif-output` (optional path)
- Steps: install Python package → run audit → upload SARIF (optional) → exit non-zero on threshold.
- Example workflow: `.github/workflows/mcp-audit-example.yml` (can be `workflow_dispatch` only to avoid breaking CI initially).
- Document in `python/README.md` and `docs/MCP_SECURITY.md`.

---

### D8 — Documentation

| Doc | Content |
|-----|---------|
| `docs/MCP_SECURITY.md` | How to pin, scan, policy, rug-pull detection, CI usage |
| `python/README.md` | Update with audit/bom/registry commands |
| `docs/API.md` | New `/api/mcp/*` endpoints |
| `README.md` | Phase 1 feature blurb + quick start |

Update `docs/STRATEGY.md` Phase 1 section: mark items complete when done.

---

## Explicit non-goals (Phase 1)

Do **not** implement in this PR — defer to Phase 2 or GAPS:

- Full `@agentshield/runtime` SDK / IFC labels / quarantine LLM
- LangChain / MAF / CrewAI middleware
- Policy DSL beyond YAML allowlist (no CEL/Rego compiler yet)
- Human-in-the-loop approval UI (record findings only)
- Adaptive multi-turn red team (Phase 3)
- Shadow-MCP network discovery
- CycloneDX export (unless trivial; else GAPS)

---

## Acceptance criteria (Definition of Done)

- [ ] `cd python && pytest` — all tests pass (existing + new adapter/registry/audit/bom tests)
- [ ] `cd server && npm test` — all tests pass (including new MCP route tests)
- [ ] `agentshield mcp audit` runs end-to-end on `python/examples/tools_poisoned.json` and exits non-zero with SARIF output
- [ ] Rug-pull test: pin benign tool → mutate description → verify returns drift finding
- [ ] Allowlist test: tool not in policy → `deny` when `fail_closed: true`
- [ ] Server `POST /api/mcp/audit` returns scored findings + optional SARIF
- [ ] AgentBOM JSON validates against documented schema
- [ ] GitHub Action documented and runnable via example workflow
- [ ] No secrets in logs; JWT auth on new API routes
- [ ] **`docs/PHASE1_GAPS.md` committed** (see below)

---

## Architecture constraints

1. **Python owns MCP security logic**; Node is API/CLI orchestration and existing UI.
2. **Deterministic oracles > regex** for pass/fail on tool execution (already in Assure layer).
3. **Fail-closed by default** in production policy mode.
4. **Minimal diff** — extend PR #2 modules; avoid parallel implementations.
5. Branch name: `cursor/phase1-mcp-firewall-f5d6`.

---

## Suggested file layout (new)

```text
python/agentshield/
  mcp/
    adapter.py      # D1
    registry.py     # D2
    audit.py        # D3
    policy.py       # D4
  bom/
    agentbom.py     # D6
server/
  routes/mcp.js
  services/mcp/
    runAudit.js
  models/McpPinRegistry.js   # if Mongo-backed
  tests/mcp.audit.test.js
.github/
  actions/mcp-audit/action.yml
  workflows/mcp-audit-example.yml
docs/
  MCP_SECURITY.md
  PHASE1_GAPS.md    # required deliverable — see GFI section
```

---

## Testing checklist

| Test | Fixture |
|------|---------|
| Pin stability | `python/examples/tool.json` |
| Poisoning detected | `python/examples/tools_poisoned.json` |
| Oracle fail | `python/examples/trace_fail.json` |
| Rug pull | unit test: same name, changed description → drift |
| Allowlist deny | policy with empty `allowed_tools`, fail_closed |
| SARIF valid | JSON schema smoke test or snapshot |
| API auth | 401 without JWT on `/api/mcp/*` |

---

## Git / PR instructions

1. Branch from latest `main`: `git checkout -b cursor/phase1-mcp-firewall-f5d6`
2. Commit incrementally with conventional commits (`feat(mcp): ...`).
3. Push: `git push -u origin cursor/phase1-mcp-firewall-f5d6`
4. Open **draft PR** against `main` with:
   - Summary of D1–D8
   - Test commands run
   - Link to `docs/PHASE1_GAPS.md`
5. Mark PR ready for review when all acceptance criteria pass.

---

## Good First Issues (GFI) — instructions for this agent

> **Do NOT create GitHub issues or GFI markdown during Phase 1 implementation.**

At PR completion, you **must** create `docs/PHASE1_GAPS.md` with:

1. **Completed** — checklist of D1–D8 items done
2. **Deferred** — scoped items intentionally skipped (with reason)
3. **Known limitations** — edge cases not handled
4. **Suggested contributor tasks** — bullet list of safe, isolated follow-ups (sized for `good first issue` vs `help wanted`)

Example GAPS entries:

```markdown
## Suggested contributor tasks (for maintainers to turn into issues later)

- [good first issue] Add 20 poisoning pattern fixtures to python/tests/fixtures/
- [good first issue] Document MCP stdio transport setup for Windows
- [help wanted] CycloneDX export from AgentBOM
- [help wanted] Dashboard UI: MCP audit results panel
```

**Maintainers / planning agent** will convert `PHASE1_GAPS.md` → GitHub issues **after Phase 1 merges**. This avoids duplicate work and merge conflicts with in-flight Phase 1 code.

---

## Reference

- Strategy: `docs/STRATEGY.md`
- Threat model: `docs/threat-model.md`
- OWASP MCP Top 10: MCP03 tool poisoning, MCP06 intent flow / indirect injection
- PR #2 merge: `9a23791`

---

*Handoff prepared for coding agent. Questions → open PR comment or issue on the Phase 1 PR.*
