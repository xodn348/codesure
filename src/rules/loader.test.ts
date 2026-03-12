import { describe, test, expect } from 'bun:test';
import { parseRuleFile, filterRulesByLanguage } from './loader.js';
import { writeFileSync, unlinkSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

function writeTempYaml(content: string): string {
  const dir = join(tmpdir(), 'codesure-test');
  mkdirSync(dir, { recursive: true });
  const filePath = join(dir, `rule-${Date.now()}-${Math.random().toString(36).slice(2)}.yaml`);
  writeFileSync(filePath, content, 'utf-8');
  return filePath;
}

function cleanup(filePath: string): void {
  try {
    unlinkSync(filePath);
  } catch {
    // ignore
  }
}

const VALID_RULE_YAML = `
rules:
  - id: js.security.eval-injection
    category: vulnerability
    taxonomy: EXM
    severity: critical
    languages: [javascript, typescript]
    pattern: 'eval\\s*\\('
    pattern-not: 'eval\\s*\\(\\s*["\\x27]'
    message: "eval() with non-literal input — potential code injection"
    fix: "Use JSON.parse() or a safe parser instead"
    metadata:
      cwe: CWE-95
      owasp: A03:2021
      confidence: high
`;

const MISSING_ID_YAML = `
rules:
  - category: vulnerability
    severity: critical
    languages: [javascript]
    pattern: 'eval\\s*\\('
    message: "eval() with non-literal input"
`;

const MULTI_LANG_YAML = `
rules:
  - id: js.security.eval-injection
    category: vulnerability
    severity: critical
    languages: [javascript]
    pattern: 'eval\\s*\\('
    message: "eval() with non-literal input"
  - id: ts.security.eval-injection
    category: vulnerability
    severity: critical
    languages: [typescript]
    pattern: 'eval\\s*\\('
    message: "eval() with non-literal input"
  - id: py.security.exec-injection
    category: vulnerability
    severity: high
    languages: [python]
    pattern: 'exec\\s*\\('
    message: "exec() with non-literal input"
`;

describe('parseRuleFile', () => {
  test('valid YAML with 1 rule returns array with 1 SecurityRule', () => {
    const filePath = writeTempYaml(VALID_RULE_YAML);
    try {
      const rules = parseRuleFile(filePath);
      expect(rules).toHaveLength(1);
      expect(rules[0].id).toBe('js.security.eval-injection');
      expect(rules[0].category).toBe('vulnerability');
      expect(rules[0].severity).toBe('critical');
      expect(rules[0].languages).toContain('javascript');
      expect(rules[0].languages).toContain('typescript');
      expect(rules[0].message).toBe('eval() with non-literal input — potential code injection');
    } finally {
      cleanup(filePath);
    }
  });

  test('invalid YAML (missing required field id) returns empty array without throwing', () => {
    const filePath = writeTempYaml(MISSING_ID_YAML);
    try {
      let result: ReturnType<typeof parseRuleFile> | undefined;
      expect(() => {
        result = parseRuleFile(filePath);
      }).not.toThrow();
      expect(result).toBeDefined();
      expect(result).toHaveLength(0);
    } finally {
      cleanup(filePath);
    }
  });

  test('pattern-not in YAML is converted to pattern_not in SecurityRule', () => {
    const filePath = writeTempYaml(VALID_RULE_YAML);
    try {
      const rules = parseRuleFile(filePath);
      expect(rules).toHaveLength(1);
      expect(rules[0].pattern_not).toBeDefined();
      expect(typeof rules[0].pattern_not).toBe('string');
      // Ensure the raw YAML key 'pattern-not' is NOT present on the object
      expect((rules[0] as unknown as Record<string, unknown>)['pattern-not']).toBeUndefined();
    } finally {
      cleanup(filePath);
    }
  });
});

describe('filterRulesByLanguage', () => {
  let rules: ReturnType<typeof parseRuleFile>;

  const filePath = writeTempYaml(MULTI_LANG_YAML);
  rules = parseRuleFile(filePath);
  cleanup(filePath);

  test('filter with "js" alias returns javascript rules', () => {
    const filtered = filterRulesByLanguage(rules, 'js');
    expect(filtered.length).toBeGreaterThan(0);
    expect(filtered.every((r) => r.languages.includes('javascript'))).toBe(true);
  });

  test('filter with "ts" alias returns typescript rules', () => {
    const filtered = filterRulesByLanguage(rules, 'ts');
    expect(filtered.length).toBeGreaterThan(0);
    expect(filtered.every((r) => r.languages.includes('typescript'))).toBe(true);
  });

  test('filter with "python" returns python rules only', () => {
    const filtered = filterRulesByLanguage(rules, 'python');
    expect(filtered.length).toBeGreaterThan(0);
    expect(filtered.every((r) => r.languages.includes('python'))).toBe(true);
    // Should not include javascript or typescript rules
    expect(filtered.some((r) => r.languages.includes('javascript'))).toBe(false);
    expect(filtered.some((r) => r.languages.includes('typescript'))).toBe(false);
  });
});
