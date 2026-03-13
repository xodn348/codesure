import { mkdir, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { CodeSureError } from '../errors.js';

const INDEX_URL =
  'https://raw.githubusercontent.com/xodn348/codesure-rules/main/rules-index.json';

interface RulesIndex {
  rules: Array<{ id: string; url: string }>;
}

interface UpdateResult {
  updated: number;
  message: string;
}

function getCacheDir(): string {
  return join(homedir(), '.codesure', 'community-rules');
}

async function ensureCacheDir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
}

async function fetchRulesIndex(source: string): Promise<RulesIndex | null> {
  const response = await fetch(source);
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new CodeSureError('RULES_FETCH_FAILED', `Failed to fetch rules index: HTTP ${response.status}`, { retryable: true, context: { source, status: response.status } });
  }
  return (await response.json()) as RulesIndex;
}

async function downloadRule(
  rule: RulesIndex['rules'][number],
  cacheDir: string
): Promise<boolean> {
  try {
    const response = await fetch(rule.url);
    if (!response.ok) return false;
    const content = await response.text();
    await writeFile(join(cacheDir, `${rule.id}.yaml`), content, 'utf-8');
    return true;
  } catch {
    return false;
  }
}

export async function updateRules(source?: string): Promise<UpdateResult> {
  const indexUrl = source ?? INDEX_URL;

  try {
    const index = await fetchRulesIndex(indexUrl);
    if (!index) {
      return {
        updated: 0,
        message: 'Community rules repository not yet populated. Check back later.',
      };
    }

    const cacheDir = getCacheDir();
    await ensureCacheDir(cacheDir);

    const results = await Promise.all(
      index.rules.map((rule) => downloadRule(rule, cacheDir))
    );
    const updated = results.filter(Boolean).length;

    return {
      updated,
      message:
        updated === index.rules.length
          ? `Successfully updated ${updated} community rule(s).`
          : `Updated ${updated} of ${index.rules.length} rule(s). Some downloads failed.`,
    };
  } catch (cause) {
    const message = cause instanceof CodeSureError ? cause.message : cause instanceof Error ? cause.message : String(cause);
    return { updated: 0, message: `Failed to fetch community rules: ${message}` };
  }
}
