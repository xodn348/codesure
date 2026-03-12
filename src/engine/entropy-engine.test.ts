import { describe, test, expect } from 'bun:test';
import { scanEntropy, calculateEntropy } from './entropy-engine.js';

describe('scanEntropy', () => {
  test('hex string in sensitive var -> detected', () => {
    const code = 'const apiKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";';
    const findings = scanEntropy(code);

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.entropy).toBeGreaterThan(4.5);
  });

  test('non-sensitive var with high entropy -> NOT detected', () => {
    const code = 'const data = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";';
    const findings = scanEntropy(code);

    expect(findings.length).toBe(0);
  });

  test('UUID -> exempt', () => {
    const code = 'const token = "550e8400-e29b-41d4-a716-446655440000";';
    const findings = scanEntropy(code);

    expect(findings.length).toBe(0);
  });

  test('JWT -> exempt', () => {
    const code = 'const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";';
    const findings = scanEntropy(code);

    expect(findings.length).toBe(0);
  });

  test('normal english string -> below threshold', () => {
    const code = 'const message = "hello world this is a normal string";';
    const findings = scanEntropy(code);

    expect(findings.length).toBe(0);
  });
});

describe('calculateEntropy', () => {
  test('calculateEntropy basics', () => {
    expect(calculateEntropy('')).toBe(0);
    expect(calculateEntropy('aaaa')).toBe(0);
    expect(calculateEntropy('ab')).toBeCloseTo(1.0, 1);
  });
});
