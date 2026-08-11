/**
 * SARIF 2.1.0 exporter for Assure findings / oracle results.
 * Aligns with python/agentshield/assure/sarif.py
 */

const LEVEL = {
  Critical: 'error',
  High: 'error',
  Medium: 'warning',
  Low: 'note'
};

function toFinding(item) {
  return {
    ruleId: item.oracle_id || item.rule_id || item.name || 'finding',
    message: item.evidence || item.message || '',
    severity: item.severity || 'Medium',
    impact: item.impact || 'hygiene',
    confidence: item.confidence != null ? item.confidence : 0.5,
    taxonomy: item.taxonomy || [],
    evidence: item.evidence || '',
    passed: item.passed === true
  };
}

function findingsToSarif(items = [], options = {}) {
  const findings = items.map(toFinding).filter((f) => !f.passed);
  const rules = new Map();
  const results = [];

  for (const finding of findings) {
    if (!rules.has(finding.ruleId)) {
      rules.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.ruleId,
        shortDescription: { text: finding.message || finding.ruleId },
        fullDescription: { text: finding.evidence || finding.message || finding.ruleId },
        defaultConfiguration: { level: LEVEL[finding.severity] || 'warning' },
        properties: {
          'security-severity': finding.severity,
          impact: finding.impact,
          taxonomy: finding.taxonomy
        }
      });
    }
    results.push({
      ruleId: finding.ruleId,
      level: LEVEL[finding.severity] || 'warning',
      message: { text: finding.message || finding.ruleId },
      properties: {
        confidence: finding.confidence,
        impact: finding.impact,
        taxonomy: finding.taxonomy,
        evidence: finding.evidence
      }
    });
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: options.toolName || 'agentshield',
            version: options.toolVersion || '0.1.0',
            informationUri: 'https://github.com/new-world-coder/agentshield',
            rules: [...rules.values()]
          }
        },
        results
      }
    ]
  };
}

module.exports = { findingsToSarif, toFinding };
