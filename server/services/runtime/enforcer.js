'use strict';

const { Integrity, Confidentiality, FlowLabels } = require('./labels');
const { AuditChain } = require('./auditChain');

const EnforcementDecision = {
  ALLOW: 'allow',
  DENY: 'deny',
  REQUIRE_APPROVAL: 'require_approval',
  WARN: 'warn'
};

class ExecutionContext {
  constructor() {
    this.labelsInScope = FlowLabels.trustedPublic();
    this.contentRecords = [];
    this.toolCalls = [];
  }

  ingest(content, labels = FlowLabels.trustedPublic(), source = 'user', ref = null) {
    this.labelsInScope = this.labelsInScope.merge(labels);
    this.contentRecords.push({
      ref: ref || `content_${this.contentRecords.length + 1}`,
      labels: labels.toDict(),
      source,
      byteLength: Buffer.byteLength(content, 'utf8')
    });
    return this.labelsInScope;
  }

  static fromTrace(trace) {
    const ctx = new ExecutionContext();
    for (const step of trace.steps || []) {
      if (step.type === 'content') {
        ctx.ingest(
          step.content || '',
          FlowLabels.fromDict(step.labels),
          step.source || 'unknown',
          step.ref
        );
      }
    }
    if (trace.labels_in_scope) {
      ctx.labelsInScope = FlowLabels.fromDict(trace.labels_in_scope);
    }
    return ctx;
  }

  get hasUntrusted() {
    return this.labelsInScope.integrity === Integrity.UNTRUSTED;
  }

  get hasPrivate() {
    return this.labelsInScope.confidentiality === Confidentiality.PRIVATE;
  }
}

function matchesIfcRule(rule, ctx) {
  const when = rule.when || {};
  for (const [key, expected] of Object.entries(when)) {
    const norm = String(expected).toLowerCase();
    if (key === 'integrity_in_scope' || key === 'integrity') {
      const actual = ctx.hasUntrusted ? 'untrusted' : 'trusted';
      if (actual !== norm) return false;
    } else if (key === 'confidentiality_in_scope' || key === 'confidentiality') {
      const actual = ctx.hasPrivate ? 'private' : 'public';
      if (actual !== norm) return false;
    } else {
      return false;
    }
  }
  return true;
}

function decideToolPolicy(toolPolicy, toolName) {
  const name = (toolName || '').trim();
  if (!name) return { decision: 'deny', reason: 'empty_tool_name' };
  for (const pattern of toolPolicy.blocked_patterns || []) {
    try {
      if (new RegExp(pattern).test(name)) {
        return { decision: 'deny', reason: `blocked_pattern:${pattern}` };
      }
    } catch {
      if (pattern && name.includes(pattern)) {
        return { decision: 'deny', reason: `blocked_pattern:${pattern}` };
      }
    }
  }
  const allowed = new Set(toolPolicy.allowed_tools || []);
  const approval = new Set(toolPolicy.approval_required || []);
  if (allowed.has(name)) return { decision: 'allow', reason: 'allowlisted' };
  if (approval.has(name)) return { decision: 'require_approval', reason: 'approval_required' };
  if (toolPolicy.fail_closed !== false) {
    return { decision: 'deny', reason: 'not_allowlisted' };
  }
  return { decision: 'require_approval', reason: 'fail_open_approval' };
}

function evaluateTrace(trace, runtimePolicy = {}) {
  const mode = (runtimePolicy.mode || 'production').toLowerCase();
  const toolPolicy = runtimePolicy.tool_policy || runtimePolicy;
  const ifcRules = runtimePolicy.ifc_rules || [];
  const sensitive = new Set(runtimePolicy.sensitive_tools || []);
  const ctx = ExecutionContext.fromTrace(trace);
  const results = [];

  for (const step of trace.steps || []) {
    if (step.type === 'content') {
      ctx.ingest(
        step.content || '',
        FlowLabels.fromDict(step.labels),
        step.source || 'external'
      );
      continue;
    }
    if (step.type !== 'tool_call') continue;

    const call = step.call || step;
    const name = String(call.name || call.tool || '').trim();
    const start = Date.now();
    let decision = EnforcementDecision.ALLOW;
    let reason = 'allowed';
    let ruleId = 'runtime.allow';

    const blocked = toolPolicy.blocked_patterns || [];
    for (const pattern of blocked) {
      try {
        if (new RegExp(pattern).test(name)) {
          decision = EnforcementDecision.DENY;
          reason = `blocked_pattern:${pattern}`;
          ruleId = 'tool_policy.blocked';
          break;
        }
      } catch {
        if (pattern && name.includes(pattern)) {
          decision = EnforcementDecision.DENY;
          reason = `blocked_pattern:${pattern}`;
          ruleId = 'tool_policy.blocked';
          break;
        }
      }
    }

    if (decision === EnforcementDecision.ALLOW) {
      for (let i = 0; i < ifcRules.length; i++) {
        const rule = ifcRules[i];
        if (!matchesIfcRule(rule, ctx)) continue;
        if ((rule.deny_tools || []).includes(name)) {
          decision = EnforcementDecision.DENY;
          reason = rule.reason || 'ifc_rule';
          ruleId = `ifc.deny.${i}`;
          break;
        }
        if ((rule.require_approval_tools || []).includes(name)) {
          decision = EnforcementDecision.REQUIRE_APPROVAL;
          reason = rule.reason || 'ifc_rule';
          ruleId = `ifc.approval.${i}`;
          break;
        }
      }
    }

    if (decision === EnforcementDecision.ALLOW && ctx.hasUntrusted && sensitive.has(name)) {
      decision = EnforcementDecision.DENY;
      reason = 'sensitive_tool_with_untrusted_in_scope';
      ruleId = 'ifc.sensitive_default';
    }

    if (decision === EnforcementDecision.ALLOW) {
      const tp = decideToolPolicy(toolPolicy, name);
      if (tp.decision === 'deny') {
        decision = EnforcementDecision.DENY;
        reason = tp.reason;
        ruleId = 'tool_policy.deny';
      } else if (tp.decision === 'require_approval') {
        decision = EnforcementDecision.REQUIRE_APPROVAL;
        reason = tp.reason;
        ruleId = 'tool_policy.approval';
      }
    }

    if (mode === 'development' && decision === EnforcementDecision.DENY) {
      decision = EnforcementDecision.WARN;
    }

    results.push({
      decision,
      tool_name: name,
      reason,
      rule_id: ruleId,
      elapsed_ms: Date.now() - start,
      labels_in_scope: ctx.labelsInScope.toDict()
    });
  }

  return results;
}

module.exports = {
  EnforcementDecision,
  ExecutionContext,
  evaluateTrace,
  decideToolPolicy,
  AuditChain
};
