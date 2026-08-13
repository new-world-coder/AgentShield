# Good First Issues — Post Phase 1

**Phase 1 status:** Merged (PR #3). See `docs/PHASE1_GAPS.md` for deferrals and limitations.  
**Purpose:** Ready-to-use GitHub issue bodies for open-source contributors.  
**Labels:** `good first issue` · `help wanted` · `documentation` · `enhancement` · `phase-2-prep`

Maintainers: issues below are also filed on GitHub (search by title). Update this doc if issue numbers change.

---

## How to contribute

1. Comment on an issue before starting (avoid duplicate work).
2. Fork → branch → PR against `main`.
3. Run tests:
   ```bash
   cd python && pip install -e ".[dev]" && pytest
   cd server && npm test
   cd server && npm run test:mcp   # after #5 lands
   ```
4. Link the issue in your PR (`Fixes #NNN`).

**Do not pick:** Phase 2 core (IFC middleware, quarantine LLM, LangChain bindings) unless labeled `phase-2-prep` and scoped to pure utilities/tests.

---

## Good first issues

### GFI-1: Add MCP poisoning & typosquat test fixtures

**Labels:** `good first issue`, `enhancement`  
**Size:** Small (2–4 hours)

**Goal**  
Expand regression coverage for `python/agentshield/mcp/scan.py` with realistic malicious tool definitions.

**Tasks**
- Add JSON fixtures under `python/tests/fixtures/mcp/`:
  - Hidden instruction in `description` (markdown/HTML comment)
  - Typosquat near a trusted name (e.g. `read_file` vs `read_fille`)
  - Shadow tool name collision
  - Clean benign tool (expected `ok: true`)
- Add parametrized tests asserting `rule_id` and severity for each fixture.

**Acceptance criteria**
- [ ] ≥4 new fixtures + tests in `python/tests/test_mcp_scan.py` (or new file)
- [ ] `pytest python/tests/test_mcp_scan.py` passes
- [ ] No real harmful payloads in fixture text (use benign placeholders)

**Entry points**
- `python/agentshield/mcp/scan.py`
- `python/examples/tools_poisoned.json` (reference)

---

### GFI-2: Document MCP stdio transport on Windows

**Labels:** `good first issue`, `documentation`  
**Size:** Small (1–2 hours)

**Goal**  
Help Windows contributors run `agentshield mcp audit` with stdio MCP servers.

**Tasks**
- Add section to `docs/MCP_SECURITY.md`: command quoting, `cmd` vs PowerShell, PATH, WSL note.
- Include one working example using `python/examples/server_file.json` pattern.

**Acceptance criteria**
- [ ] New “Windows” subsection in `docs/MCP_SECURITY.md`
- [ ] Commands are copy-pasteable (no shell-specific bugs)

---

### GFI-3: Clean tools fixture + CI example (exit 0)

**Labels:** `good first issue`, `enhancement`  
**Size:** Small (2–3 hours)

**Goal**  
Provide a **passing** MCP audit path for CI demos (today’s example uses poisoned fixtures + `continue-on-error`).

**Tasks**
- Add `python/examples/tools_clean.json` matching `python/examples/policy.yaml`.
- Add workflow snippet to `docs/MCP_SECURITY.md` or extend `.github/workflows/mcp-audit-example.yml` with a second job that expects success.
- Document expected exit code 0.

**Acceptance criteria**
- [ ] `agentshield mcp audit --tools examples/tools_clean.json --policy examples/policy.yaml --ignore-unpinned` exits 0
- [ ] Docs or workflow show green-path usage

---

### GFI-4: “Pin then verify” tutorial in MCP_SECURITY.md

**Labels:** `good first issue`, `documentation`  
**Size:** Small (1–2 hours)

**Goal**  
Step-by-step rug-pull detection walkthrough for new users.

**Tasks**
- Document: pin → mutate description in JSON → verify → expect `schema_drift`.
- Optional: ASCII diagram of pin hash fields.

**Acceptance criteria**
- [ ] New tutorial section with exact CLI commands
- [ ] Expected output snippet for drift failure

**Entry points**
- `docs/MCP_SECURITY.md`
- `python/agentshield/mcp/registry.py`

---

### GFI-5: Add `npm run test:mcp` script alias

**Labels:** `good first issue`, `enhancement`  
**Size:** Tiny (30 min)

**Goal**  
One command for MCP API integration tests.

**Tasks**
- Add to `server/package.json`:
  ```json
  "test:mcp": "jest --config jest.assure.config.js mcp.audit.test.js"
  ```
- Mention in `docs/MCP_SECURITY.md` and `docs/DEVELOPMENT.md`.

**Acceptance criteria**
- [ ] `cd server && npm run test:mcp` runs `server/tests/mcp.audit.test.js`
- [ ] CI unchanged or updated if beneficial

---

## Help wanted

### HW-1: CycloneDX export from AgentBOM

**Labels:** `help wanted`, `enhancement`  
**Size:** Medium

**Goal**  
Export AgentBOM v1 to CycloneDX 1.5 for supply-chain tooling.

**Tasks**
- Add `python/agentshield/bom/cyclonedx.py` with `agentbom_to_cyclonedx(bom: dict) -> dict`.
- CLI: `agentshield bom export --format cyclonedx --audit-report …`
- Unit tests with snapshot JSON.

**Non-goals**  
Full SPDX; signing.

**Entry points**
- `python/agentshield/bom/agentbom.py`
- `python/agentshield/cli.py`

---

### HW-2: Mongoose `McpPinRegistry` model (persistent pins)

**Labels:** `help wanted`, `enhancement`  
**Size:** Medium

**Goal**  
Replace in-memory pin store with MongoDB for multi-replica deployments.

**Tasks**
- Add `server/models/McpPinRegistry.js` (userId, serverId, toolName, pinHash, snapshot, pinnedAt).
- Refactor `server/services/mcp/pinRegistry.js` to use model with in-memory fallback for tests.
- Migration note in `docs/MCP_SECURITY.md`.

**Acceptance criteria**
- [ ] API `/api/mcp/pins` persists across server restart when Mongo available
- [ ] Existing `server/tests/mcp.audit.test.js` pass without Mongo (mock/in-memory)

---

### HW-3: Dashboard UI — MCP audit results panel

**Labels:** `help wanted`, `enhancement`  
**Size:** Medium–Large

**Goal**  
Surface MCP audit reports in the Next.js dashboard.

**Tasks**
- New page or section: upload tools JSON + policy → call `POST /api/mcp/audit`.
- Show severity, findings table, link to SARIF download.
- Use existing MUI patterns from `client/src/pages/`.

**Non-goals**  
Human approval workflow (HW-5).

**Entry points**
- `client/src/pages/dashboard.tsx`
- `server/routes/mcp.js`

---

### HW-4: Optional official MCP Python SDK adapter

**Labels:** `help wanted`, `enhancement`  
**Size:** Medium

**Goal**  
Feature-detect wrapper around official MCP SDK when installed; fall back to minimal client.

**Tasks**
- Optional extra: `pip install agentshield[mcp-sdk]`
- `python/agentshield/mcp/adapter.py`: try SDK transport, else existing JSON-RPC.
- Document in `python/README.md`.

**Acceptance criteria**
- [ ] Works without SDK (current behavior unchanged)
- [ ] Integration test skipped if SDK not installed

---

### HW-5: Persist audit reports + `GET /api/mcp/bom/:auditId`

**Labels:** `help wanted`, `enhancement`  
**Size:** Medium

**Goal**  
Store audit runs and retrieve AgentBOM by ID (currently 501 / inline only).

**Tasks**
- Model `McpAuditReport` with executionId, findings, bom, userId, createdAt.
- Implement `GET /api/mcp/bom/:auditId` (remove 501).
- TTL or pagination for list endpoint (optional).

**Entry points**
- `server/routes/mcp.js` (check current 501 handler)
- `server/services/mcp/runAudit.js`

---

### HW-6: Align Node ↔ Python typosquat scoring

**Labels:** `help wanted`, `enhancement`  
**Size:** Medium

**Goal**  
Shared test vectors so `server/services/mcp/scan.js` and `python/agentshield/mcp/scan.py` agree at threshold boundaries.

**Tasks**
- Add `python/tests/fixtures/typosquat_pairs.json` with expected scores/decisions.
- Port same vectors to `server/tests/mcp.typosquat.test.js`.
- Document algorithm choice or unify on one implementation.

**Known issue**  
Node uses Levenshtein approximation; Python uses `SequenceMatcher` (`docs/PHASE1_GAPS.md`).

---

### HW-7: Human approval queue UX (Phase 1.5)

**Labels:** `help wanted`, `enhancement`  
**Size:** Large

**Goal**  
UI for tools with `require_approval` firewall decision (recorded as High finding today).

**Tasks**
- Queue model: pending tool call, policy reason, approve/deny.
- API: `POST /api/mcp/approvals/:id/resolve`.
- Wire to audit report display.

**Non-goals**  
Phase 2 runtime SDK enforcement (that's in-process middleware).

---

## Phase 2 prep (starter — not full SDK)

These prepare Phase 2 without blocking the runtime agent. Pick only if comfortable with Python types/tests.

### P2-1: IFC label types + propagation helpers (pure Python)

**Labels:** `good first issue`, `phase-2-prep`  
**Size:** Small–Medium

**Goal**  
`Trusted` / `Untrusted` / `Public` / `Private` labels with merge rules (most restrictive wins).

**Tasks**
- New module `python/agentshield/runtime/labels.py` (no middleware yet).
- Tests: merge trusted+untrusted → untrusted; public+private → private.

**Non-goals**  
LangChain integration, quarantine LLM.

---

### P2-2: Audit log hash-chain utility

**Labels:** `good first issue`, `phase-2-prep`  
**Size:** Small

**Goal**  
Tamper-evident JSONL audit entries for future runtime SDK.

**Tasks**
- `python/agentshield/runtime/audit_chain.py`: append entry with prev_hash, entry_hash.
- Verify chain function + tests.

---

### P2-3: Policy DSL parser tests (YAML → internal AST stub)

**Labels:** `help wanted`, `phase-2-prep`  
**Size:** Medium

**Goal**  
Test harness for future CEL/Rego compiler; parse extended policy fields without executing.

**Tasks**
- Extend policy schema with commented future fields (egress, data classes).
- Parser returns AST dict; snapshot tests only.

**Entry points**
- `python/agentshield/mcp/policy.py`

---

## Explicitly NOT good first issues (maintainer / Phase 2 agent)

- Full `@agentshield/runtime` IFC middleware
- Quarantine LLM pattern
- LangChain / MAF / CrewAI bindings
- Adaptive multi-turn red team (Phase 3)
- Shadow-MCP network discovery

---

*Generated after Phase 1 merge (PR #3). Source: `docs/PHASE1_GAPS.md`.*
