'use strict';

const fs = require('fs');
const path = require('path');
const { evaluateTrace } = require('../services/runtime');

const examplesDir = path.join(__dirname, '../../python/examples');
const trace = JSON.parse(
  fs.readFileSync(path.join(examplesDir, 'runtime_trace.json'), 'utf8')
);
const policy = {
  mode: 'production',
  tool_policy: {
    fail_closed: true,
    allowed_tools: ['search_docs', 'read_file'],
    approval_required: ['write_file'],
    blocked_patterns: []
  },
  ifc_rules: [
    {
      when: { integrity_in_scope: 'untrusted' },
      deny_tools: ['write_file', 'delete_file', 'send_email'],
      reason: 'untrusted_blocks_sensitive'
    }
  ],
  sensitive_tools: ['write_file', 'delete_file', 'send_email']
};

describe('Runtime SDK (Node mirror)', () => {
  it('allows search_docs then denies write_file after untrusted content', () => {
    const results = evaluateTrace(trace, policy);
    expect(results).toHaveLength(2);
    expect(results[0].decision).toBe('allow');
    expect(results[0].tool_name).toBe('search_docs');
    expect(results[1].decision).toBe('deny');
    expect(results[1].tool_name).toBe('write_file');
  });

  it('warns in development mode instead of deny', () => {
    const devPolicy = { ...policy, mode: 'development' };
    const results = evaluateTrace(trace, devPolicy);
    expect(results[1].decision).toBe('warn');
  });
});
