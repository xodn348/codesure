import { describe, test, expect } from 'bun:test';
import { updateRules } from './update-rules.js';

describe('updateRules', () => {
  test('returns graceful message when repo empty or unreachable', async () => {
    const result = await updateRules();
    expect(result.message).toBeDefined();
    expect(typeof result.updated).toBe('number');
  });

  test('updated count is a non-negative number', async () => {
    const result = await updateRules();
    expect(result.updated).toBeGreaterThanOrEqual(0);
  });

  test('does not throw on network error with invalid source', async () => {
    const result = await updateRules('https://invalid.example.invalid/rules-index.json');
    expect(result.updated).toBe(0);
    expect(result.message).toContain('Failed to fetch community rules');
  });

  test('returns graceful message for 404 source', async () => {
    const result = await updateRules(
      'https://raw.githubusercontent.com/xodn348/codesure-rules/main/rules-index.json'
    );
    expect(typeof result.updated).toBe('number');
    expect(result.message).toBeDefined();
  });
});
