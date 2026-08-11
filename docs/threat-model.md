# AgentShield Threat Model

**Version:** 2.0  
**Last Updated:** 2026-08-11  
**Next Review:** 2026-11-11  
**Maps to:** OWASP LLM Top 10 · OWASP Agentic / ASI Top 10 · MCP Top 10  
**Related:** [STRATEGY.md](./STRATEGY.md)

## Purpose & Scope

AgentShield identifies, tests, and (increasingly) **enforces** security controls for agentic AI systems. This threat model covers:

- Conversational and multi-step agents  
- Tool-integrated agents and **MCP hosts/servers**  
- Multi-agent orchestration  
- RAG / memory-backed agents  
- Runtime policy enforcement paths (Enforce layer)

**Hero asset:** the agent **execution graph** — prompts → memory → tools/MCP → side effects → other agents.

## Assets

### Primary
- System prompts and policy packs  
- User / tool / RAG inputs (untrusted by default)  
- Long-term memory and session state  
- Model outputs and tool call plans  
- **MCP tool metadata** (name, description, input schema) — integrity-critical  

### External
- API keys, OAuth tokens (confused-deputy risk)  
- Databases, filesystems, browsers, shells  
- Third-party MCP servers and model providers  
- CI artifacts (SARIF, AgentBOM) and signed pack registries  

## Attacker Capabilities

- Untrusted user prompts and multi-turn persuasion  
- Indirect injection via RAG, tickets, email, web, **tool results**  
- Malicious or compromised MCP servers (poisoned descriptions, rug pulls)  
- Typosquat / shadow tools on the same host  
- Stolen or over-scoped OAuth / API credentials  
- Parallel tool races and TOCTOU on schema after policy check  
- Compromised judge / evaluation models (when semantic judges are used)

## Taxonomy Mapping

### OWASP LLM Top 10

| ID | Threat | Impact | Likelihood | Severity | AgentShield coverage |
|----|--------|--------|------------|----------|----------------------|
| LLM01 | Prompt Injection | 9 | 9 | Critical | Oracles + mutational packs |
| LLM02 | Sensitive Information Disclosure | 9 | 7 | Critical | Egress/secret oracles |
| LLM03 | Supply Chain | 8 | 6 | High | MCP pin/scan; AgentBOM (Phase 1+) |
| LLM04 | Data and Model Poisoning | 8 | 5 | High | RAG/memory packs (Phase 3) |
| LLM05 | Improper Output Handling | 7 | 7 | High | Output oracles + DLP hooks |
| LLM06 | Excessive Agency | 9 | 7 | Critical | Tool allowlist / MCP firewall |
| LLM07 | System Prompt Leakage | 8 | 7 | Critical | Extraction probes + oracles |
| LLM08 | Vector / Embedding Weaknesses | 7 | 5 | High | RAG packs (Phase 3) |
| LLM09 | Misinformation | 6 | 8 | High | Semantic judge (optional) |
| LLM10 | Unbounded Consumption | 6 | 6 | Medium | Rate / cost oracles |

### OWASP Agentic / ASI Top 10

| ID | Threat | Severity | Notes |
|----|--------|----------|-------|
| ASI01 | Agent Goal Hijack | Critical | Overrides objectives via injection / persuasion |
| ASI02 | Tool Misuse | Critical | Forbidden tool fired — **action oracle primary signal** |
| ASI03 | Identity / Role Spoofing | High | Role confusion, fake admin personas |
| ASI04 | Memory Poisoning | High | Persistent malicious context |
| ASI05 | Cascading Hallucinations | High | Multi-agent error amplification |
| ASI06 | Unexpected Code Execution | Critical | Shell/interpreter tools |
| ASI07 | Agent Communication Poisoning | High | Inter-agent message injection |
| ASI08 | Rogue Agents | Critical | Compromised peer in swarm |
| ASI09 | Human–Agent Trust Exploitation | High | Approval fatigue / social engineering |
| ASI10 | Resource Overwhelm | Medium | Parallel tool storms, cost bombs |

### MCP Top 10

| ID | Threat | Severity | Phase 1 control |
|----|--------|----------|-----------------|
| MCP01 | Tool Description Poisoning | Critical | `mcp.scan` description heuristics |
| MCP02 | Schema Rug Pull / Mutation | Critical | `mcp.pin` hash of name+description+schema |
| MCP03 | Shadow Tools | High | Duplicate/near-name detection |
| MCP04 | Unsigned / Untrusted Servers | High | Trust allowlist primitive |
| MCP05 | Confused Deputy (OAuth/MCP tokens) | Critical | Scope + allowlist (Phase 1+) |
| MCP06 | Excessive Tool Permissions | High | Least-privilege allowlist |
| MCP07 | Indirect Injection via Tool Results | Critical | Treat tool results as untrusted (IFC Phase 2) |
| MCP08 | Typosquat MCP Servers/Tools | High | Distance / lookalike scan |
| MCP09 | Open / Unauthenticated Endpoints | High | Endpoint posture checks |
| MCP10 | Cross-Server Data Exfiltration | Critical | Egress oracles + policy |

## Impact-Based Severity (not pattern echo)

Severity is derived from **what would happen if the agent complied**, not whether the response text echoed the attack string.

| Impact class | Examples | Default severity |
|--------------|----------|------------------|
| Irreversible side effect | `rm`, money move, email send, `git push` to main | Critical |
| Secret egress | API keys, PII, system prompt dump | Critical |
| Privilege change | Role elevation, new tool grants | High |
| Policy bypass without side effect | Jailbreak text only | High → Medium if no tool fire |
| Resource abuse | Unbounded calls, huge context | Medium |
| Hygiene / info | Weak validation, noisy logs | Low |

**Scoring formula (Assure):**

```text
finding_score = impact_weight × confidence
suite_score   = min(100, Σ finding_score normalized by suite budget)
```

Regex/text matches contribute **confidence ≤ 0.4**. Action oracles (forbidden tool fired, secret in egress, schema hash drift) contribute **confidence ≥ 0.9**.

## Mitigation Controls

### Assure (shift-left)
- Versioned mutational payload packs tagged LLM/ASI/MCP  
- Deterministic action oracles; optional semantic judge  
- SARIF export for CI gates  
- Continuous regression on pinned MCP schemas  

### Enforce (runtime — Phase 1/2)
- MCP schema pin + reject-on-drift  
- Tool allowlist / require-approval  
- Fail-closed production policy  
- IFC labels on untrusted tool/RAG content (Phase 2)  

### Govern
- Telemetry + replay of tool graphs  
- Drift alerts on pack/schema versions  
- Compliance mapping to LLM / ASI / MCP taxonomies  

## AgentShield Test → Taxonomy Map

| Test / control | LLM | ASI | MCP |
|----------------|-----|-----|-----|
| `prompt-injection` packs | LLM01 | ASI01 | — |
| `system-prompt-extraction` | LLM07 | — | — |
| `data-exfiltration` + egress oracle | LLM02 | — | MCP10 |
| `tool-abuse` + tool-fire oracle | LLM06 | ASI02/06 | MCP06 |
| `role-confusion` | — | ASI03 | — |
| `jailbreaking` | LLM01 | ASI01 | — |
| MCP pin/scan | LLM03 | — | MCP01–04,08 |
| Memory/RAG packs (Phase 3) | LLM04/08 | ASI04 | MCP07 |

## Remediation Priority

| Priority | Focus |
|----------|--------|
| **P0** | MCP pin + description poisoning scan; secret egress; forbidden tool fire |
| **P1** | Goal hijack / injection packs; allowlist; system prompt protection |
| **P2** | Memory/RAG; multi-agent; cost/unbounded consumption |
| **P3** | Output hygiene; monitoring polish |

## Compliance Anchors

- OWASP LLM Top 10, OWASP Agentic / ASI Top 10, MCP Top 10  
- NIST AI RMF, ISO/IEC 23053  
- GDPR / CCPA / HIPAA / SOC 2 / EU AI Act (Govern packs — later)

## Review Cadence

Threat models stale quickly in agent security. Review at least quarterly, or when:

- New MCP capability classes ship  
- A production incident involves tool/MCP misuse  
- OWASP publishes taxonomy revisions  

---

*Replaces Threat Model v1.0 (2024). See STRATEGY.md for product phasing.*
