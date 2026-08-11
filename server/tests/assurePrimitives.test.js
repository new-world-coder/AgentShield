/**
 * Unit tests for Assure Phase 0 primitives (oracles, SARIF, packs, scoring).
 */

const { evaluateTrace } = require('../services/assure/oracles');
const { findingsToSarif } = require('../services/assure/sarif');
const { scoreOracleResults, severityForImpact } = require('../services/assure/scoring');
const { expandPacks } = require('../services/assure/packs');

describe('Assure oracles', () => {
  test('fails on forbidden tool fire and secret egress', () => {
    const results = evaluateTrace(
      {
        tool_calls: [{ name: 'shell', result: 'ok' }],
        egress: 'token sk-abcdefghijklmnopqrstuvwxyz123456'
      },
      { forbiddenTools: ['shell'] }
    );
    const byId = Object.fromEntries(results.map((r) => [r.oracle_id, r]));
    expect(byId.forbidden_tool_fire.passed).toBe(false);
    expect(byId.secret_egress.passed).toBe(false);
  });

  test('passes clean trace', () => {
    const results = evaluateTrace(
      {
        tool_calls: [{ name: 'get_time', result: 'noon' }],
        egress: 'The time is noon',
        pin_verification: { ok: true }
      },
      { forbiddenTools: ['shell'] }
    );
    expect(results.every((r) => r.passed)).toBe(true);
  });
});

describe('Impact scoring + SARIF', () => {
  test('severity from impact not echo', () => {
    expect(severityForImpact('irreversible_side_effect', 0.95)).toBe('Critical');
    expect(severityForImpact('hygiene', 0.9)).toBe('Low');
  });

  test('scoreOracleResults and SARIF export', () => {
    const oracles = evaluateTrace(
      { tool_calls: [{ name: 'shell' }], pin_verification: { ok: false, reason: 'digest_mismatch' } },
      { forbiddenTools: ['shell'] }
    );
    const scored = scoreOracleResults(oracles);
    expect(scored.severity).toBe('Critical');
    expect(scored.score).toBeGreaterThan(0);

    const sarif = findingsToSarif(oracles);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });
});

describe('Mutational packs', () => {
  test('expands with encoding mutations', () => {
    const pack = expandPacks();
    expect(pack.count).toBeGreaterThanOrEqual(4 * 4);
    expect(pack.cases.some((c) => c.mutation === 'base64')).toBe(true);
    expect(pack.cases.some((c) => c.taxonomy.includes('MCP01'))).toBe(true);
  });
});
