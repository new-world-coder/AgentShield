# Phase 2 Gaps & Follow-ups

**Status after Phase 2 PR:** Runtime SDK core shipped (IFC, quarantine, policy DSL, enforcer, audit chain, CLI, Node API mirror).  
**Convert to GitHub issues after merge** — do not duplicate in-flight Phase 2.5 work.

---

## Completed (Phase 2)

- [x] IFC labels (`trusted`/`untrusted`, `public`/`private`) + merge rules
- [x] Execution context + trace replay
- [x] Quarantine store (untrusted → opaque reference)
- [x] Runtime policy DSL (YAML) extending Phase 1 tool policy
- [x] `RuntimeEnforcer` + `AgentShieldRuntime` middleware facade
- [x] Production fail-closed / development warn modes
- [x] Hash-chained audit log (append + verify)
- [x] CLI: `runtime check`, `runtime audit-verify`, `runtime policy-ast`
- [x] Node API: `POST /api/runtime/check`, `POST /api/runtime/audit/verify`
- [x] Docs: `docs/RUNTIME.md`

---

## Deferred

| Item | Reason |
|------|--------|
| LangChain / CrewAI / MAF middleware | Phase 2.5 bindings |
| Full CEL / Rego policy compiler | AST stub only; execution in Phase 2.5 |
| Human approval queue UX | Phase 1.5 / HW-7 |
| Dashboard runtime panel | Contributor issue |
| Sub-20ms policy benchmark gate | Needs perf harness |
| Real quarantine LLM processor | Phase 2.5 — separate summarizer model |
| Signed audit log export | Phase 4 governance |

---

## Known limitations

- Node enforcer mirrors Python logic but does not invoke Python subprocess for `/api/runtime/check`.
- Quarantine returns placeholders only; no bundled summarizer LLM.
- IFC rules match simple `when` keys; no compound boolean expressions yet.
- Audit chain verification loads full file into memory.
- Development mode converts `deny` → `warn` but does not auto-allow blocked tool execution in host (host must interpret `warn`).

---

## Suggested contributor tasks

- [good first issue] Add LangChain `before_tool_call` example in `python/examples/`
- [good first issue] Benchmark policy check latency; document p99 in RUNTIME.md
- [help wanted] Dashboard panel for runtime check results
- [help wanted] CEL expression evaluator for `ifc_rules.when` (subset)
- [help wanted] Persist runtime audit logs via Mongo + API list endpoint
- [help wanted] Wire Chrome extension to call `/api/runtime/check`

---

*Generated at Phase 2 PR completion.*
