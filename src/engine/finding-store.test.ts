import { describe, test, expect } from 'bun:test';
import { rememberFindings, getFinding } from './finding-store.js';
import type { Finding } from '../types.js';

function makeFinding(id: string): Finding {
  return {
    id,
    severity: 'high',
    category: 'vulnerability',
    confidence: 80,
    rule_id: `rule-${id}`,
    message: `finding ${id}`,
    location: { file: 'a.ts', line: 1 },
  };
}

describe('finding-store', () => {
  test('remember then get returns the finding', () => {
    const finding = makeFinding('remember-1');
    rememberFindings([finding]);

    expect(getFinding('remember-1')).toEqual(finding);
  });

  test('unknown id returns undefined', () => {
    expect(getFinding('does-not-exist-xyz')).toBeUndefined();
  });

  test('evicts oldest past the cap of 500', () => {
    const findings = Array.from({ length: 600 }, (_, i) => makeFinding(`evict-${i}`));
    rememberFindings(findings);

    // The first 100 (600 - 500) inserted should be evicted.
    expect(getFinding('evict-0')).toBeUndefined();
    expect(getFinding('evict-99')).toBeUndefined();
    // The most recent 500 should still be present.
    expect(getFinding('evict-100')).toBeDefined();
    expect(getFinding('evict-599')).toBeDefined();
  });
});
