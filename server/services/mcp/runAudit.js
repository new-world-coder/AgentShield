'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { scanTools } = require('./scan');
const { decide } = require('./firewall');
const { pinTool, hashTool } = require('./pin');
const { memoryPinAll, memoryVerify, memoryList } = require('./pinRegistry');
const { findingsToSarif } = require('../assure/sarif');
const { scoreOracleResults } = require('../assure/scoring');

function normalizeTools(input) {
  if (Array.isArray(input)) return input;
  if (input && Array.isArray(input.tools)) return input.tools;
  throw new Error("tools must be a list or { tools: [] }");
}

function scanToFinding(f) {
  return {
    rule_id: f.rule_id,
    message: f.message,
    impact: f.severity === 'Critical' || f.severity === 'High' ? 'supply_chain_integrity' : 'hygiene',
    confidence: 0.85,
    severity: f.severity,
    taxonomy: f.taxonomy ? [f.taxonomy] : [],
    evidence: f.evidence || '',
    passed: false
  };
}

function driftToFinding(f) {
  return {
    rule_id: f.rule_id,
    message: f.message,
    impact: 'supply_chain_integrity',
    confidence: f.rule_id === 'schema_drift' ? 0.99 : 0.9,
    severity: f.severity,
    taxonomy: [f.taxonomy || 'MCP02'],
    evidence: `${f.expected_hash || ''}|${f.live_hash || ''}`,
    passed: false
  };
}

function decisionToFinding(d) {
  if (d.decision === 'allow') return null;
  if (d.decision === 'require_approval') {
    return {
      rule_id: 'require_approval',
      message: `Tool '${d.tool_name}' requires human approval`,
      impact: 'excessive_agency',
      confidence: 0.9,
      severity: 'High',
      taxonomy: ['MCP05'],
      evidence: d.reason || '',
      passed: false
    };
  }
  return {
    rule_id: 'firewall_deny',
    message: `Tool '${d.tool_name}' denied by policy`,
    impact: 'excessive_agency',
    confidence: 0.95,
    severity: 'High',
    taxonomy: ['MCP05'],
    evidence: d.reason || '',
    passed: false
  };
}

function buildAgentBom(report, { agent = {}, policy = {} } = {}) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of report.findings || []) {
    if (f.passed) continue;
    const sev = String(f.severity || 'Low').toLowerCase();
    if (summary[sev] !== undefined) summary[sev] += 1;
  }
  const decisions = Object.fromEntries(
    (report.firewall_decisions || []).map((d) => [d.tool_name, d.decision])
  );
  return {
    bomVersion: '1.0',
    agentShieldVersion: '0.1.0',
    generatedAt: new Date().toISOString(),
    agent: {
      name: agent.name || report.server_id || 'agent',
      adapter: agent.adapter || 'api',
      model: agent.model || ''
    },
    mcpServers: [
      {
        id: report.server_id || 'default',
        transport: 'file',
        tools: (report.tools || []).map((t) => ({
          name: t.name,
          pinHash: '',
          decision: decisions[t.name] || 'unknown'
        }))
      }
    ],
    policies: policy && Object.keys(policy).length
      ? [{ name: 'inline', path: '', hash: hashTool({ name: 'policy', description: JSON.stringify(policy), inputSchema: {} }) }]
      : [],
    findingsSummary: summary
  };
}

function runAuditNode({
  tools,
  policy = {},
  userId = 'anonymous',
  serverId = 'default',
  verifyPins = true,
  includeUnpinned = true,
  agent = {}
}) {
  const toolList = normalizeTools(tools);
  const scan = scanTools(toolList);
  let drift = verifyPins ? memoryVerify(userId, toolList, serverId) : [];
  if (!includeUnpinned) {
    drift = drift.filter((d) => d.rule_id !== 'unpinned_tool');
  }
  const firewall_decisions = toolList.map((t) => decide(t.name, policy));
  const findings = [
    ...scan.findings.map(scanToFinding),
    ...drift.map(driftToFinding),
    ...firewall_decisions.map(decisionToFinding).filter(Boolean)
  ];
  const scored = scoreOracleResults(findings);
  const report = {
    server_id: serverId,
    tools: toolList,
    scan_findings: scan.findings,
    drift_findings: drift,
    firewall_decisions,
    findings: scored.findings || findings,
    score: scored.score,
    severity: scored.severity,
    summary: `score=${scored.score} severity=${scored.severity}`,
    ok: (scored.statistics?.failed ?? findings.length) === 0,
    error: null
  };
  report.agentbom = buildAgentBom(report, { agent, policy });
  return report;
}

function tryPythonAudit({ tools, policy, pinsPath, serverId = 'default' }) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agentshield-mcp-'));
  try {
    const toolsFile = path.join(tmp, 'tools.json');
    const policyFile = path.join(tmp, 'policy.json');
    const outFile = path.join(tmp, 'audit.json');
    fs.writeFileSync(toolsFile, JSON.stringify({ tools: normalizeTools(tools) }));
    fs.writeFileSync(policyFile, JSON.stringify(policy || { fail_closed: true, allowed_tools: [] }));
    const pythonRoot = path.resolve(__dirname, '../../../python');
    const args = [
      '-m',
      'agentshield.cli',
      'mcp',
      'audit',
      '--tools',
      toolsFile,
      '--policy',
      policyFile,
      '--server-id',
      serverId,
      '--out',
      outFile
    ];
    if (pinsPath) {
      args.push('--pins', pinsPath);
    } else {
      args.push('--ignore-unpinned');
    }
    const result = spawnSync('python3', args, {
      cwd: pythonRoot,
      encoding: 'utf8',
      env: { ...process.env, PYTHONPATH: pythonRoot },
      timeout: 30000
    });
    if (result.error || !fs.existsSync(outFile)) {
      return null;
    }
    return JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch {
    return null;
  } finally {
    try {
      fs.rmSync(tmp, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
}

function runAudit(options) {
  // Prefer Python subprocess for parity; fall back to Node orchestration.
  if (options.preferPython !== false) {
    const py = tryPythonAudit(options);
    if (py) return { ...py, engine: 'python' };
  }
  return { ...runAuditNode(options), engine: 'node' };
}

module.exports = {
  runAudit,
  runAuditNode,
  tryPythonAudit,
  normalizeTools,
  buildAgentBom,
  pinTool,
  memoryPinAll,
  memoryVerify,
  memoryList
};
