'use strict';

const express = require('express');
const Joi = require('joi');
const {
  runAudit,
  normalizeTools,
  memoryPinAll,
  memoryVerify,
  memoryList,
  buildAgentBom
} = require('../services/mcp/runAudit');
const { findingsToSarif } = require('../services/assure/sarif');

const router = express.Router();

const toolsSchema = Joi.alternatives().try(
  Joi.array().items(Joi.object({ name: Joi.string().required() }).unknown(true)),
  Joi.object({
    tools: Joi.array().items(Joi.object({ name: Joi.string().required() }).unknown(true)).required()
  })
);

const policySchema = Joi.object({
  fail_closed: Joi.boolean().default(true),
  allowed_tools: Joi.array().items(Joi.string()).default([]),
  approval_required: Joi.array().items(Joi.string()).default([]),
  blocked_patterns: Joi.array().items(Joi.string()).default([])
}).default({});

function userId(req) {
  return req.user?._id?.toString?.() || req.user?.id || 'anonymous';
}

function stripSecrets(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const clone = Array.isArray(obj) ? [...obj] : { ...obj };
  for (const key of Object.keys(clone)) {
    const lower = key.toLowerCase();
    if (
      lower.includes('token') ||
      lower.includes('secret') ||
      lower.includes('password') ||
      lower === 'authorization' ||
      lower === 'env'
    ) {
      clone[key] = '[REDACTED]';
    } else if (typeof clone[key] === 'object') {
      clone[key] = stripSecrets(clone[key]);
    }
  }
  return clone;
}

router.post('/audit', async (req, res) => {
  try {
    const schema = Joi.object({
      tools: toolsSchema.required(),
      policy: policySchema,
      server_id: Joi.string().default('default'),
      verify_pins: Joi.boolean().default(true),
      include_unpinned: Joi.boolean().default(true),
      prefer_python: Joi.boolean().default(true),
      include_sarif: Joi.boolean().default(false),
      agent: Joi.object({
        name: Joi.string().allow(''),
        adapter: Joi.string().allow(''),
        model: Joi.string().allow('')
      }).default({})
    });
    const { error, value } = schema.validate(req.body, { abortEarly: false });
    if (error) {
      return res.status(400).json({ error: error.details.map((d) => d.message).join('; ') });
    }

    const report = runAudit({
      tools: value.tools,
      policy: value.policy,
      userId: userId(req),
      serverId: value.server_id,
      verifyPins: value.verify_pins,
      includeUnpinned: value.include_unpinned,
      preferPython: value.prefer_python,
      agent: value.agent
    });

    const body = { ...report };
    if (value.include_sarif) {
      body.sarif = findingsToSarif(report.findings || []);
    }
    return res.json(stripSecrets(body));
  } catch (err) {
    return res.status(500).json({ error: err.message || 'MCP audit failed' });
  }
});

router.post('/pin', async (req, res) => {
  try {
    const schema = Joi.object({
      tools: toolsSchema.required(),
      server_id: Joi.string().default('default')
    });
    const { error, value } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details.map((d) => d.message).join('; ') });
    }
    const tools = normalizeTools(value.tools);
    const pins = memoryPinAll(userId(req), tools, value.server_id);
    return res.json({ pins, count: pins.length });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Pin failed' });
  }
});

router.post('/verify', async (req, res) => {
  try {
    const schema = Joi.object({
      tools: toolsSchema.required(),
      server_id: Joi.string().default('default')
    });
    const { error, value } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details.map((d) => d.message).join('; ') });
    }
    const tools = normalizeTools(value.tools);
    const findings = memoryVerify(userId(req), tools, value.server_id);
    return res.json({ ok: findings.length === 0, findings });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Verify failed' });
  }
});

router.get('/pins', async (req, res) => {
  try {
    const serverId = req.query.server_id || undefined;
    const pins = memoryList(userId(req), serverId);
    return res.json({ pins, count: pins.length });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'List pins failed' });
  }
});

router.post('/sarif', async (req, res) => {
  try {
    const schema = Joi.object({
      tools: toolsSchema.required(),
      policy: policySchema,
      server_id: Joi.string().default('default'),
      verify_pins: Joi.boolean().default(true),
      prefer_python: Joi.boolean().default(true)
    });
    const { error, value } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details.map((d) => d.message).join('; ') });
    }
    const report = runAudit({
      tools: value.tools,
      policy: value.policy,
      userId: userId(req),
      serverId: value.server_id,
      verifyPins: value.verify_pins,
      preferPython: value.prefer_python
    });
    const sarif = findingsToSarif(report.findings || []);
    return res.json(sarif);
  } catch (err) {
    return res.status(500).json({ error: err.message || 'SARIF export failed' });
  }
});

router.get('/bom/:auditId', async (req, res) => {
  // Phase 1: audits are not persisted server-side; accept ?report= inline via POST preferred.
  return res.status(501).json({
    error: 'Audit persistence not enabled in Phase 1. Include agentbom in POST /api/mcp/audit response or POST a report to /api/mcp/bom.'
  });
});

router.post('/bom', async (req, res) => {
  try {
    const report = req.body?.audit || req.body;
    if (!report || typeof report !== 'object') {
      return res.status(400).json({ error: 'audit report object required' });
    }
    const bom = report.agentbom || buildAgentBom(report, { agent: req.body.agent || {}, policy: req.body.policy || {} });
    return res.json(bom);
  } catch (err) {
    return res.status(500).json({ error: err.message || 'BOM failed' });
  }
});

module.exports = router;
