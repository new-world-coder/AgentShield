'use strict';

const crypto = require('crypto');

function canonicalJson(value) {
  return JSON.stringify(value, Object.keys(value).sort ? undefined : undefined, 0);
}

function stableStringify(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
}

function toolFingerprint(tool) {
  const schema = tool.inputSchema || tool.input_schema || tool.parameters || {};
  return stableStringify({
    name: tool.name || '',
    description: tool.description || '',
    inputSchema: schema
  });
}

function hashTool(tool, algorithm = 'sha256') {
  return crypto.createHash(algorithm).update(toolFingerprint(tool), 'utf8').digest('hex');
}

function pinTool(tool, algorithm = 'sha256') {
  const name = String(tool.name || '').trim();
  if (!name) throw new Error('Tool must have a non-empty name');
  return {
    name,
    algorithm,
    digest: hashTool(tool, algorithm),
    fingerprint: toolFingerprint(tool)
  };
}

function verifyPin(tool, pin) {
  const liveName = String(tool.name || '').trim();
  if (liveName !== pin.name) {
    return { ok: false, reason: `name_mismatch: expected=${pin.name} live=${liveName}` };
  }
  const live = hashTool(tool, pin.algorithm || 'sha256');
  const expected = pin.digest || pin.pin_hash;
  if (live !== expected) {
    return { ok: false, reason: `digest_mismatch: expected=${expected} live=${live}` };
  }
  return { ok: true, reason: 'ok' };
}

module.exports = { toolFingerprint, hashTool, pinTool, verifyPin, stableStringify, canonicalJson };
