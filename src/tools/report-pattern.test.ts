import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { reportPattern, anonymizePattern } from './report-pattern.js';
import type { Finding, AgentInfo } from '../types.js';

const mockFinding: Finding = {
  id: 'finding-001',
  severity: 'high',
  category: 'vulnerability',
  confidence: 85,
  rule_id: 'eval-injection',
  taxonomy: 'EXS',
  message: 'Dynamic eval detected',
  location: { file: '/home/user/project/app.ts', line: 42 },
  evidence_chain: ['eval-call', 'user-input'],
};

const mockAgent: AgentInfo = { name: 'Claude Code', version: '1.0.0' };

describe('anonymizePattern', () => {
  test('strips file path from output', () => {
    const anon = anonymizePattern(mockFinding, mockAgent);
    expect(JSON.stringify(anon)).not.toContain('/home/user');
    expect(JSON.stringify(anon)).not.toContain('app.ts');
  });

  test('extracts language from file extension', () => {
    const anon = anonymizePattern(mockFinding, mockAgent);
    expect(anon.language).toBe('typescript');
  });

  test('returns unknown language when no file path', () => {
    const finding = { ...mockFinding, location: {} };
    const anon = anonymizePattern(finding, mockAgent);
    expect(anon.language).toBe('unknown');
  });

  test('maps evidence_chain to abstract indicators', () => {
    const anon = anonymizePattern(mockFinding, mockAgent);
    expect(anon.indicators).toEqual(['eval_call', 'user_input']);
  });

  test('falls back to rule_id when no evidence_chain', () => {
    const finding = { ...mockFinding, evidence_chain: undefined };
    const anon = anonymizePattern(finding, mockAgent);
    expect(anon.indicators).toEqual(['eval-injection']);
  });

  test('includes agent name and version', () => {
    const anon = anonymizePattern(mockFinding, mockAgent);
    expect(anon.agent.name).toBe('Claude Code');
    expect(anon.agent.version).toBe('1.0.0');
  });

  test('includes timestamp', () => {
    const anon = anonymizePattern(mockFinding, mockAgent);
    expect(anon.timestamp).toBeDefined();
    expect(() => new Date(anon.timestamp)).not.toThrow();
  });

  test('anonymizePattern strips sensitive data (secret.ts path)', () => {
    const finding = { ...mockFinding, location: { file: '/home/user/project/secret.ts', line: 42 } };
    const anon = anonymizePattern(finding, { name: 'Claude Code', version: '1.0.0' });
    expect(JSON.stringify(anon)).not.toContain('/home/user');
    expect(JSON.stringify(anon)).not.toContain('secret.ts');
    expect(anon.agent.name).toBe('Claude Code');
    expect(anon.timestamp).toBeDefined();
  });
});

describe('reportPattern', () => {
  const originalToken = process.env['GITHUB_TOKEN'];

  beforeEach(() => {
    delete process.env['GITHUB_TOKEN'];
  });

  afterEach(() => {
    if (originalToken !== undefined) {
      process.env['GITHUB_TOKEN'] = originalToken;
    } else {
      delete process.env['GITHUB_TOKEN'];
    }
  });

  test('no GITHUB_TOKEN → graceful degradation', async () => {
    const result = await reportPattern(mockFinding, mockAgent);
    expect(result.success).toBe(false);
    expect(result.message).toContain('GitHub token not configured');
  });

  test('returns success: false without token', async () => {
    const result = await reportPattern({ ...mockFinding }, { name: 'Claude Code', version: '1.0.0' });
    expect(result.success).toBe(false);
    expect(result.message).toContain('GitHub token not configured');
  });
});
