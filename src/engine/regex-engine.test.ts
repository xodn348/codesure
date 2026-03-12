import { describe, test, expect } from 'bun:test';
import { scanWithRegex } from './regex-engine.js';
import type { SecurityRule } from '../types.js';

const evalRule: SecurityRule = {
  id: 'js.security.eval-injection',
  category: 'vulnerability',
  severity: 'critical',
  languages: ['javascript'],
  pattern: 'eval\\s*\\(',
  pattern_not: "eval\\s*\\(\\s*['\"]",
  message: 'eval() with non-literal input',
  metadata: { confidence: 'high' },
};

describe('scanWithRegex', () => {
  test('finds eval(userInput) with expected fields', () => {
    const findings = scanWithRegex('eval(userInput)', [evalRule], 'src/app.js');

    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.category).toBe('vulnerability');
    expect(findings[0]?.confidence).toBe(80);
  });

  test('filters eval("safe") using pattern_not', () => {
    const findings = scanWithRegex('eval("safe")', [evalRule]);
    expect(findings).toHaveLength(0);
  });

  test("filters eval('safe') using pattern_not", () => {
    const findings = scanWithRegex("eval('safe')", [evalRule]);
    expect(findings).toHaveLength(0);
  });

  test('returns findings from multiple matching rules', () => {
    const functionCtorRule: SecurityRule = {
      id: 'js.security.function-constructor',
      category: 'vulnerability',
      severity: 'high',
      languages: ['javascript'],
      pattern: 'new\\s+Function\\s*\\(',
      message: 'Function constructor can execute dynamic code',
      metadata: { confidence: 'low' },
    };

    const code = 'eval(userInput);\nconst f = new Function(userInput);';
    const findings = scanWithRegex(code, [evalRule, functionCtorRule], 'src/main.js');

    expect(findings).toHaveLength(2);
    expect(findings.some((finding) => finding.rule_id === evalRule.id)).toBe(true);
    expect(findings.some((finding) => finding.rule_id === functionCtorRule.id)).toBe(true);
  });

  test('skips invalid regex rules without throwing', () => {
    const invalidRule: SecurityRule = {
      id: 'js.security.invalid',
      category: 'vulnerability',
      severity: 'medium',
      languages: ['javascript'],
      pattern: '[unterminated',
      message: 'invalid regex should be skipped',
    };

    expect(() => scanWithRegex('eval(userInput)', [invalidRule])).not.toThrow();
    const findings = scanWithRegex('eval(userInput)', [invalidRule]);
    expect(findings).toHaveLength(0);
  });

  test('returns no findings for empty code', () => {
    const findings = scanWithRegex('', [evalRule]);
    expect(findings).toHaveLength(0);
  });

  test('reports accurate line numbers', () => {
    const code = 'const a = 1;\nconst b = 2;\neval(userInput);\nconst c = 3;';
    const findings = scanWithRegex(code, [evalRule], 'src/file.js');

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.line).toBe(3);
  });

  test('uses high confidence override', () => {
    const findings = scanWithRegex('eval(userInput)', [evalRule]);
    expect(findings[0]?.confidence).toBe(80);
  });

  test('does not flag benign fetch API usage', () => {
    const code = 'const res = await fetch("/api/data", { method: "GET" });';
    const findings = scanWithRegex(code, [evalRule]);
    expect(findings).toHaveLength(0);
  });
});
