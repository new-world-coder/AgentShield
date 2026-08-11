'use strict';

function decide(toolName, policy = {}) {
  const name = String(toolName || '').trim();
  const failClosed = policy.fail_closed !== false;
  const allowed = new Set(policy.allowed_tools || policy.allowed || []);
  const approval = new Set(policy.approval_required || policy.approve || []);
  const blocked = policy.blocked_patterns || [];

  if (!name) {
    return { decision: 'deny', tool_name: '', reason: 'empty_tool_name' };
  }
  for (const pattern of blocked) {
    try {
      if (new RegExp(pattern).test(name)) {
        return { decision: 'deny', tool_name: name, reason: `blocked_pattern:${pattern}` };
      }
    } catch {
      if (pattern && name.includes(pattern)) {
        return { decision: 'deny', tool_name: name, reason: `blocked_pattern:${pattern}` };
      }
    }
  }
  if (allowed.has(name)) {
    return { decision: 'allow', tool_name: name, reason: 'allowlisted' };
  }
  if (approval.has(name)) {
    return { decision: 'require_approval', tool_name: name, reason: 'approval_required' };
  }
  if (failClosed) {
    return { decision: 'deny', tool_name: name, reason: 'not_allowlisted' };
  }
  return { decision: 'require_approval', tool_name: name, reason: 'fail_open_approval' };
}

module.exports = { decide };
