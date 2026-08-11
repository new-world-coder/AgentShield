# AgentShield Strategy — Open Agent Security Fabric

**Status:** Approved defaults for Phase 0 + Phase 1 start  
**Branch:** `cursor/phase0-mcp-firewall-f5d6`  
**Decisions:** Python-first runtime SDK · MCP firewall before adaptive Assure expansion

## Repositioning

| From | To |
|------|----|
| Web UI that fuzzes agents with known prompts | **Open Agent Security Fabric** — continuous assurance + deterministic runtime control for any agent stack |

AgentShield remains a solid pre-deploy red-team UI. The market moved past static probes and regex echo checks. The hero for the next era is **agent execution security** — not a generic AppSec scanner.

## Three Layers

1. **Assure (shift-left)** — adaptive red team, CI gates, AgentBOM/AIBOM for agents & MCP  
2. **Enforce (runtime)** — information-flow control, tool/MCP policy, quarantine, human-in-the-loop  
3. **Govern (ops)** — telemetry, drift, compliance (OWASP LLM + Agentic + MCP Top 10), incident replay

**Differentiation:** Own the full agent execution graph (prompts → memory → tools/MCP → side effects → other agents) with **deterministic policy**, not only ML classifiers.

## Architecture Sketch

```text
[ CI / Extension / API ] → Assure Engine (adaptive probes + oracles)
                ↓ findings
         Policy Compiler (packs → CEL/Rego)
                ↓
[ Agent Host ] ↔ Runtime SDK (IFC + Tool/MCP Firewall + DLP)
                ↓
         Telemetry / Replay / Risk Graph
```

## Detection Quality Bar

A **pass** must mean the unsafe *action* did not happen — not merely that the attack string was absent from the response text. Regex echo matching is retained only as a weak signal; **action oracles** are authoritative. Optional semantic judges must never be the sole gate (judge models can be compromised).

## Phased Roadmap

### Phase 0 — Foundations (this PR)

- Threat model refresh → OWASP LLM + Agentic ASI + MCP Top 10  
- Oracle-based detection (deterministic action oracles; optional semantic judge hook)  
- Mutational payload packs (encoding / taxonomy-tagged / versioned)  
- Impact-based severity scoring  
- SARIF export for CI  
- This strategy document  

### Phase 1 — MCP & Tool Firewall (start in this PR; complete later)

**In this PR (primitives):**

- Schema pin / hash (name + description + input schema)  
- Poisoning / typosquat / shadow-tool scan hooks  
- Tool allowlist primitive  

**Follow-on PRs:**

- Full MCP adapter  
- Tool approval UX  
- CI action  
- AgentBOM  

### Phase 2 — Runtime SDK (`agentshield` Python package → bindings later)

- IFC labels, quarantine models, policy DSL (YAML/CEL/Rego)  
- Fail-closed in production; warn+record in dev  
- Sub-20ms policy path target  

### Phase 3 — Adaptive red team 2.0

- Multi-turn / tree-of-attacks / goal-oriented attackers  
- RAG/memory poisoning probes  
- Differential fuzzing, synthetic twin  

### Phase 4 — Multi-agent governance + self-hardening

- Trust domains, supervisor/ShieldAgent mode  
- Counterfactual proofs, auto-policy PRs, compliance packs, air-gap  

## Priority Defaults (approved)

1. **First PR scope:** Phase 0 + Phase 1 start (this document’s deliverables)  
2. **Runtime SDK language:** **Python-first** (Node Assure surface stays; Python owns firewall/runtime primitives)  
3. **Runtime vs Assure:** **MCP firewall first**, then adaptive red-team expansion  

## Feature Pillars (full vision)

| Pillar | Focus |
|--------|--------|
| A | Adaptive red team beyond Garak/Promptfoo/PyRIT |
| B | Runtime Agent Shield SDK (IFC, tool/MCP gate, DLP) |
| C | MCP & supply-chain security (highest ROI wedge) |
| D | Multi-agent & orchestration security |
| E | Platform/DX/enterprise (UI → control plane; SARIF + CycloneDX) |
| F | Moat: counterfactual proofs, intent–action alignment, economic attacks, synthetic twin |

## Safety of AgentShield Itself

- Contain jailbreak/probe content; do not emit real harmful payloads into CI logs  
- Signed packs/releases and SBOM for AgentShield artifacts  
- No silent telemetry  
- Prefer deterministic local gates so air-gapped environments keep working  

## Package Layout (Phase 0 / 1 start)

```text
python/agentshield/
  mcp/          # pin, scan, firewall allowlist
  assure/       # oracles, packs, scoring, sarif
  packs/        # versioned mutational payload JSON
docs/
  STRATEGY.md   # this file
  threat-model.md
```

## Non-Goals for This PR

- Full `@agentshield/runtime` / IFC middleware  
- Complete CI action + AgentBOM pipeline  
- Rebuilding SQLi/XSS as the product hero (keep existing AppSec tests; demote narrative priority)  

---

*Aligned with strategic planning thread `bc-4838c96d-4b88-455b-94b6-45e446d0f5d6`.*  
*Last updated: 2026-08-11*
