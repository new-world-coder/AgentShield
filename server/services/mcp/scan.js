'use strict';

const POISON_PATTERNS = [
  {
    rule_id: 'instruction_override',
    severity: 'Critical',
    taxonomy: 'MCP01',
    re: /(ignore|disregard|override).{0,40}(previous|prior|system).{0,20}(instruction|prompt|rule)/i
  },
  {
    rule_id: 'hidden_exfil',
    severity: 'Critical',
    taxonomy: 'MCP01',
    re: /(send|exfiltrat|upload|post).{0,40}(secret|api.?key|token|password|credential)/i
  },
  {
    rule_id: 'privilege_claim',
    severity: 'High',
    taxonomy: 'MCP01',
    re: /(you (must|should) |always )?(grant|enable|use).{0,30}(admin|root|sudo|unrestricted)/i
  },
  {
    rule_id: 'do_not_tell_user',
    severity: 'High',
    taxonomy: 'MCP01',
    re: /(do not|don't|never).{0,20}(tell|inform|reveal|mention).{0,20}(user|human)/i
  },
  {
    rule_id: 'tool_priority_hijack',
    severity: 'Medium',
    taxonomy: 'MCP01',
    re: /(prefer|always use|must use).{0,30}(this tool|me first)/i
  }
];

function ratio(a, b) {
  const s = String(a).toLowerCase();
  const t = String(b).toLowerCase();
  if (s === t) return 1;
  const longer = s.length > t.length ? s : t;
  const shorter = s.length > t.length ? t : s;
  if (!longer.length) return 1;
  let matches = 0;
  for (let i = 0; i < shorter.length; i += 1) {
    if (longer.includes(shorter[i])) matches += 1;
  }
  // Use Levenshtein-lite via shared prefix/suffix + length
  let dp = Array.from({ length: s.length + 1 }, (_, i) => i);
  for (let j = 1; j <= t.length; j += 1) {
    let prev = dp[0];
    dp[0] = j;
    for (let i = 1; i <= s.length; i += 1) {
      const tmp = dp[i];
      dp[i] = s[i - 1] === t[j - 1] ? prev : 1 + Math.min(prev, dp[i], dp[i - 1]);
      prev = tmp;
    }
  }
  const dist = dp[s.length];
  return 1 - dist / Math.max(s.length, t.length, 1);
}

function scanDescription(tool) {
  const name = String(tool.name || '<unnamed>');
  const description = String(tool.description || '');
  const findings = [];
  for (const p of POISON_PATTERNS) {
    const m = description.match(p.re);
    if (m) {
      findings.push({
        tool_name: name,
        rule_id: p.rule_id,
        severity: p.severity,
        taxonomy: p.taxonomy,
        message: `Description poisoning heuristic matched: ${p.rule_id}`,
        evidence: String(m[0]).slice(0, 120)
      });
    }
  }
  return findings;
}

function scanShadowAndTyposquat(tools, { similarityThreshold = 0.82 } = {}) {
  const findings = [];
  const names = tools.map((t) => String(t.name || '').trim()).filter(Boolean);
  const seen = {};
  for (const n of names) {
    const key = n.toLowerCase();
    seen[key] = (seen[key] || 0) + 1;
  }
  for (const [key, count] of Object.entries(seen)) {
    if (count > 1) {
      findings.push({
        tool_name: key,
        rule_id: 'shadow_tool_duplicate',
        severity: 'High',
        taxonomy: 'MCP03',
        message: `Shadow tool: name appears ${count} times`,
        evidence: key
      });
    }
  }
  for (let i = 0; i < names.length; i += 1) {
    for (let j = i + 1; j < names.length; j += 1) {
      if (names[i].toLowerCase() === names[j].toLowerCase()) continue;
      const score = ratio(names[i], names[j]);
      if (score >= similarityThreshold) {
        findings.push({
          tool_name: names[i],
          rule_id: 'typosquat_lookalike',
          severity: 'High',
          taxonomy: 'MCP08',
          message: `Typosquat / lookalike pair: '${names[i]}' ~ '${names[j]}' (${score.toFixed(2)})`,
          evidence: `${names[i]}|${names[j]}|${score.toFixed(2)}`
        });
      }
    }
  }
  return findings;
}

function scanTools(tools) {
  const findings = [];
  for (const tool of tools) findings.push(...scanDescription(tool));
  findings.push(...scanShadowAndTyposquat(tools));
  const ok = !findings.some((f) => f.severity === 'Critical' || f.severity === 'High');
  return { ok, tools_scanned: tools.length, findings };
}

module.exports = { scanTools, scanDescription, scanShadowAndTyposquat };
