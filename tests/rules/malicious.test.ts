/// <reference types="bun-types" />
import { describe, test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { loadRules, filterRulesByLanguage } from '../../src/rules/loader.js';
import { scanWithRegex } from '../../src/engine/regex-engine.js';

const MALICIOUS_RULES_DIR = fileURLToPath(new URL('../../src/rules/malicious/', import.meta.url));
const FIXTURES_DIR = fileURLToPath(new URL('../fixtures/development/', import.meta.url));

const maliciousRules = loadRules(MALICIOUS_RULES_DIR);

function scanFixture(relativePath: string, language: string = 'javascript') {
  const filePath = join(FIXTURES_DIR, relativePath);
  const code = readFileSync(filePath, 'utf-8');
  const rules = filterRulesByLanguage(maliciousRules, language);
  return scanWithRegex(code, rules, filePath);
}

describe('malicious rules', () => {
  test('data-exfiltration fixture produces EXF taxonomy finding', () => {
    const findings = scanFixture('malicious/data-exfiltration.js');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((finding) => finding.taxonomy === 'EXF')).toBe(true);
  });

  test('obfuscated-eval fixture is categorized as malicious', () => {
    const findings = scanFixture('malicious/obfuscated-eval.js');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((finding) => finding.category === 'malicious')).toBe(true);
  });

  test('env-exfil fixture matches env-exfil rule id', () => {
    const findings = scanFixture('malicious/env-exfil.js');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((finding) => finding.rule_id.includes('env-exfil'))).toBe(true);
  });

  test('base64-obfuscation fixture is detected', () => {
    const findings = scanFixture('malicious/base64-obfuscation.js');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('normal fetch fixture has zero malicious findings', () => {
    const findings = scanFixture('benign/fetch-api.js');
    expect(findings).toHaveLength(0);
  });
});
