import { describe, expect, it } from 'bun:test';
import { scanCode } from '../../src/tools/scan-code.js';

describe('scan_code integration', () => {
  it('returns findings for JavaScript eval(input) pattern', async () => {
    const code = 'eval(req.body.code);';
    const result = await scanCode(code, 'javascript', 'integration-eval.js');

    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings.some((finding) => finding.severity === 'critical' || finding.severity === 'high')).toBeTrue();
  });

  it('returns no findings for safe JavaScript code', async () => {
    const code = 'const x = "hello world";';
    const result = await scanCode(code, 'javascript', 'integration-safe.js');

    expect(result.findings.length).toBe(0);
  });

  it('returns findings for Python subprocess shell=True pattern', async () => {
    const code = 'import subprocess\nsubprocess.call(cmd, shell=True)';
    const result = await scanCode(code, 'python', 'integration-subprocess.py');

    expect(result.findings.length).toBeGreaterThanOrEqual(1);
  });
});
