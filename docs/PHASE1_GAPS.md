# Phase 1 Gaps & Follow-ups

**Branch:** `cursor/phase1-mcp-firewall-f5d6`  
**Status after Phase 1 PR:** Implementation complete for D1–D8; items below are intentional deferrals and contributor fodder.  
**Note for maintainers:** Convert suggested tasks into GitHub issues / good-first-issue labels **after merge**. Do not treat this file as an issue tracker.

---

## Completed (D1–D8)

- [x] **D1** MCP adapter — file / stdio / HTTP(SSE) transports (`python/agentshield/mcp/adapter.py`)
- [x] **D2** Pin registry + rug-pull / schema drift (`registry.py`, CLI `mcp pin-registry`)
- [x] **D3** Integrated audit pipeline (`audit.py`, CLI `mcp audit`)
- [x] **D4** Config-driven policy YAML/JSON (`policy.py`, env overrides)
- [x] **D5** Server API `/api/mcp/*` + Node mirrors + `server/tests/mcp.audit.test.js`
- [x] **D6** AgentBOM v1 (`python/agentshield/bom/agentbom.py`, CLI `bom generate`, audit embedding)
- [x] **D7** GitHub composite action + example workflow (`.github/actions/mcp-audit`, `mcp-audit-example.yml`)
- [x] **D8** Docs — `MCP_SECURITY.md`, API/README/STRATEGY/python README updates
- [x] **This file** — `docs/PHASE1_GAPS.md`

---

## Deferred (with reason)

| Item | Reason |
|------|--------|
| Human-in-the-loop approval UI | Explicit Phase 1 non-goal; `require_approval` recorded as High finding only |
| CEL / Rego policy compiler | Phase 2 policy DSL |
| Runtime IFC / quarantine SDK | Phase 2 `@agentshield/runtime` |
| LangChain / CrewAI / MAF middleware | Phase 2 bindings |
| CycloneDX export from AgentBOM | Optional stretch; not required for v1 BOM |
| Shadow-MCP network discovery | Out of scope; needs host telemetry |
| Persistent Mongo pin store as source of truth | JSON + in-memory user store sufficient for v1; Mongo model deferred |
| Official MCP Python SDK hard dependency | Minimal JSON-RPC client ships; optional SDK can wrap later |
| Audit result persistence / `GET /api/mcp/bom/:auditId` | Returns 501; BOM included on audit response + `POST /api/mcp/bom` |

---

## Known limitations

- Stdio/HTTP adapters speak a **minimal** `tools/list` JSON-RPC subset; full MCP session lifecycle (initialize, notifications, streaming tool calls) is not implemented.
- SSE parsing takes the last `data:` JSON payload; exotic multi-event servers may need a richer client.
- Node scan typosquat similarity uses a Levenshtein approximation; Python uses `SequenceMatcher` — rare score differences at the threshold boundary.
- Server pin registry is **per-process in-memory** (plus optional file path in Python CLI); multi-replica deployments need shared storage.
- GitHub Action example uses the **poisoned** fixture and is `workflow_dispatch` + `continue-on-error` so default CI stays green.
- Policy YAML parser is a built-in subset unless PyYAML is installed (`pip install agentshield[yaml]`).
- `prefer_python` subprocess from Node requires `python3` + editable install / `PYTHONPATH=python`; otherwise Node orchestration runs.

---

## Suggested contributor tasks (for maintainers to turn into issues later)

- [good first issue] Add more poisoning / typosquat fixtures under `python/tests/fixtures/` and assert rule_ids
- [good first issue] Document MCP stdio transport setup on Windows (command quoting, PATH)
- [good first issue] Add a *clean* tools fixture + CI example that expects exit 0
- [good first issue] Expand `docs/MCP_SECURITY.md` with a short “pin then verify” tutorial GIF/screenshots
- [good first issue] Wire `npm run test:mcp` alias in `server/package.json`
- [help wanted] CycloneDX 1.5 export from AgentBOM
- [help wanted] Mongoose `McpPinRegistry` model + migrate API off in-memory map
- [help wanted] Dashboard UI panel for MCP audit results / SARIF deep links
- [help wanted] Optional dependency on official MCP Python SDK with feature-detect wrapper
- [help wanted] Persist audit reports and implement `GET /api/mcp/bom/:auditId`
- [help wanted] Human approval queue UX for `require_approval` decisions (Phase 1.5)
- [help wanted] Align Node ↔ Python typosquat scoring to shared test vectors

---

*Generated at Phase 1 PR completion. Maintainers own issue creation from this list.*
