import { describe, test, expect } from 'bun:test';
import { analyzeChain } from './chain-engine.js';
import type { Finding, TaxonomyCode } from '../types.js';

function mockFinding(taxonomy: TaxonomyCode, confidence: number, file: string): Finding {
  return {
    id: `${taxonomy}-${confidence}`,
    severity: 'medium',
    category: 'malicious',
    confidence,
    rule_id: `rule.${taxonomy.toLowerCase()}`,
    taxonomy,
    message: `${taxonomy} finding`,
    location: { file },
  };
}

describe('analyzeChain', () => {
  test('EXS+EXM+EXF chain -> confidence boost on EXF', () => {
    const findings: Finding[] = [
      mockFinding('EXS', 50, 'file.js'),
      mockFinding('EXM', 60, 'file.js'),
      mockFinding('EXF', 40, 'file.js'),
    ];

    const result = analyzeChain(findings);
    const exfFinding = result.find((finding) => finding.taxonomy === 'EXF');

    expect(exfFinding).toBeDefined();
    expect(exfFinding?.confidence).toBeGreaterThan(40);
  });

  test('DEF+EXM chain -> EXM confidence boost', () => {
    const findings: Finding[] = [
      mockFinding('DEF', 50, 'file.js'),
      mockFinding('EXM', 40, 'file.js'),
    ];

    const result = analyzeChain(findings);
    const exmFinding = result.find((finding) => finding.taxonomy === 'EXM');

    expect(exmFinding).toBeDefined();
    expect(exmFinding?.confidence).toBeGreaterThan(40);
  });

  test('single indicator -> no boost', () => {
    const findings: Finding[] = [mockFinding('EXM', 30, 'file.js')];
    const result = analyzeChain(findings);

    expect(result[0]?.confidence).toBe(30);
  });
});
