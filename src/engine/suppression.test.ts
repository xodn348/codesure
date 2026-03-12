import { describe, test, expect } from 'bun:test';
import { parseSuppression, applySuppression } from './suppression.js';
import type { Finding } from '../types.js';

const base: Finding = {
  id: 'f1', severity: 'critical', category: 'vulnerability',
  confidence: 80, rule_id: 'eval-injection', message: 'eval', location: {},
};

describe('parseSuppression', () => {
  test('specific rule', () => {
    expect(parseSuppression('// codesure-ignore: eval-injection', 1)?.ruleIds).toEqual(['eval-injection']);
  });

  test('multiple rules', () => {
    expect(parseSuppression('// codesure-ignore: r1, r2', 1)?.ruleIds).toEqual(['r1', 'r2']);
  });

  test('suppress-all (no rule-id)', () => {
    expect(parseSuppression('// codesure-ignore', 1)?.ruleIds).toBeNull();
  });

  test('python hash comment', () => {
    expect(parseSuppression('# codesure-ignore: exec-injection', 1)?.ruleIds).toEqual(['exec-injection']);
  });

  test('non-suppression line returns null', () => {
    expect(parseSuppression('const x = eval(y)', 1)).toBeNull();
  });
});

describe('applySuppression', () => {
  test('specific rule suppresses matching finding', () => {
    const code = '// codesure-ignore: eval-injection\neval(req.body.code);';
    const result = applySuppression([{ ...base, location: { line: 2 } }], code);
    expect(result[0].suppressed).toBe(true);
    expect(result[0].suppression_rule).toBe('eval-injection');
  });

  test('suppress-all suppresses any finding', () => {
    const code = '// codesure-ignore\neval(req.body.code);';
    const result = applySuppression([{ ...base, location: { line: 2 } }], code);
    expect(result[0].suppressed).toBe(true);
    expect(result[0].suppression_rule).toBe('all');
  });

  test('no suppression on unsuppressed line', () => {
    const code = 'eval(req.body.code);';
    const result = applySuppression([{ ...base, location: { line: 1 } }], code);
    expect(result[0].suppressed).toBeUndefined();
  });

  test('wrong rule-id does not suppress', () => {
    const code = '// codesure-ignore: other-rule\neval(req.body.code);';
    const result = applySuppression([{ ...base, location: { line: 2 } }], code);
    expect(result[0].suppressed).toBeUndefined();
  });

  test('finding stays in results when suppressed (audit trail)', () => {
    const code = '// codesure-ignore\neval(req.body.code);';
    const result = applySuppression([{ ...base, location: { line: 2 } }], code);
    expect(result.length).toBe(1);
  });
});
