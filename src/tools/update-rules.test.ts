import { describe, test, expect, afterEach } from 'bun:test';
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

describe('updateRules source URL validation', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test('rejects an http:// source without fetching', async () => {
    const fetched: string[] = [];
    globalThis.fetch = (async (input: unknown) => {
      fetched.push(String(input));
      return new Response('{}', { status: 200 });
    }) as typeof fetch;

    const result = await updateRules('http://raw.githubusercontent.com/foo/rules-index.json');

    expect(fetched).toHaveLength(0);
    expect(result.updated).toBe(0);
    expect(result.message).toMatch(/https/i);
  });

  test('rejects a non-allowlisted https host without fetching', async () => {
    const fetched: string[] = [];
    globalThis.fetch = (async (input: unknown) => {
      fetched.push(String(input));
      return new Response('{}', { status: 200 });
    }) as typeof fetch;

    const result = await updateRules('https://evil.example.com/rules-index.json');

    expect(fetched).toHaveLength(0);
    expect(result.updated).toBe(0);
    expect(result.message).toMatch(/allowlist/i);
  });

  test('accepts raw.githubusercontent.com and proceeds to fetch', async () => {
    const fetched: string[] = [];
    globalThis.fetch = (async (input: unknown) => {
      fetched.push(String(input));
      return new Response(JSON.stringify({ rules: [] }), { status: 200 });
    }) as typeof fetch;

    const source = 'https://raw.githubusercontent.com/xodn348/codesure-rules/main/rules-index.json';
    const result = await updateRules(source);

    expect(fetched).toEqual([source]);
    expect(result.message).toContain('Successfully updated');
  });
});
