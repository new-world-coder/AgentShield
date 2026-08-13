'use strict';

const express = require('express');
const Joi = require('joi');
const { evaluateTrace } = require('../services/runtime');
const { AuditChain } = require('../services/runtime/auditChain');

const router = express.Router();

const traceSchema = Joi.object({
  agent: Joi.string().optional(),
  steps: Joi.array()
    .items(
      Joi.object({
        type: Joi.string().valid('content', 'tool_call').required(),
        content: Joi.string().optional(),
        source: Joi.string().optional(),
        labels: Joi.object().optional(),
        call: Joi.object().optional(),
        name: Joi.string().optional()
      }).unknown(true)
    )
    .required()
}).unknown(true);

const policySchema = Joi.object({
  mode: Joi.string().valid('production', 'development').default('production'),
  fail_closed: Joi.boolean().optional(),
  tool_policy: Joi.object().optional(),
  allowed_tools: Joi.array().items(Joi.string()).optional(),
  approval_required: Joi.array().items(Joi.string()).optional(),
  blocked_patterns: Joi.array().items(Joi.string()).optional(),
  ifc_rules: Joi.array().items(Joi.object()).optional(),
  sensitive_tools: Joi.array().items(Joi.string()).optional()
}).default({});

router.post('/check', async (req, res) => {
  try {
    const { error: traceErr, value: trace } = traceSchema.validate(req.body.trace || req.body);
    if (traceErr) {
      return res.status(400).json({ error: traceErr.message });
    }
    const { error: polErr, value: policy } = policySchema.validate(req.body.policy || {});
    if (polErr) {
      return res.status(400).json({ error: polErr.message });
    }

    const results = evaluateTrace(trace, policy);
    const blocked = results.some(r =>
      ['deny', 'require_approval'].includes(r.decision)
    );

    res.json({
      ok: !blocked,
      results,
      labels_in_scope: results.length ? results[results.length - 1].labels_in_scope : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/audit/verify', async (req, res) => {
  try {
    const entries = req.body.entries;
    if (!Array.isArray(entries)) {
      return res.status(400).json({ error: 'entries array required' });
    }
    const chain = new AuditChain();
    chain._entries = entries;
    const verdict = chain.verify();
    res.json(verdict);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
