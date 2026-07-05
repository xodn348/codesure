import { mkdir, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { CodeSureError } from '../errors.js';

const INDEX_URL =
  'https://raw.githubusercontent.com/xodn348/codesure-rules/main/rules-index.json';

/**
 * Hosts allowed to serve community rules by default.
 *
 * Downloaded rules become trusted regex at scan time (see {@link downloadRule}),
 * so the fetch origin is the security boundary against SSRF and rule-poisoning.
 * Restricting to GitHub-owned hosts keeps an attacker from redirecting the
 * fetch at an internal endpoint or a hostile rule server.
 */
const ALLOWED_RULE_HOSTS = new Set(['raw.githubusercontent.com', 'github.com']);

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

/**
 * Validates that a rule URL is safe to fetch before any network call.
 *
 * Enforces the fetch security boundary: only `https://` URLs whose host is in
 * {@link ALLOWED_RULE_HOSTS} may be fetched. This blocks SSRF and rule-poisoning
 * via caller-supplied `source` values or `url` fields inside a downloaded index.
 * Set `CODESURE_ALLOW_CUSTOM_RULE_HOST=1` to bypass the host allowlist (power
 * users hosting their own rule mirror); the `https://` requirement always holds.
 *
 * @param rawUrl - Candidate URL (the caller-supplied source or a rule's `url`).
 * @throws {CodeSureError} RULES_FETCH_FAILED when the URL is malformed, is not
 *   `https://`, or targets a non-allowlisted host.
 */
function assertAllowedRuleUrl(rawUrl: string): void {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new CodeSureError('RULES_FETCH_FAILED', `Invalid rule source URL: ${rawUrl}`, {
      retryable: false,
      userMessage: 'The rule source is not a valid URL. Use an https:// URL hosted on GitHub.',
      context: { url: rawUrl },
    });
  }

  if (parsed.protocol !== 'https:') {
    throw new CodeSureError('RULES_FETCH_FAILED', `Rule source must use https:// (got ${parsed.protocol}): ${rawUrl}`, {
      retryable: false,
      userMessage: 'Rule sources must be served over https://. http, file, ftp, and other schemes are rejected.',
      context: { url: rawUrl, protocol: parsed.protocol },
    });
  }

  const allowCustomHost = process.env.CODESURE_ALLOW_CUSTOM_RULE_HOST === '1';
  if (!allowCustomHost && !ALLOWED_RULE_HOSTS.has(parsed.hostname)) {
    throw new CodeSureError('RULES_FETCH_FAILED', `Rule source host not allowlisted: ${parsed.hostname}`, {
      retryable: false,
      userMessage: `Rule sources must be hosted on ${[...ALLOWED_RULE_HOSTS].join(' or ')}. Set CODESURE_ALLOW_CUSTOM_RULE_HOST=1 to override.`,
      context: { url: rawUrl, host: parsed.hostname },
    });
  }
}

async function fetchRulesIndex(source: string): Promise<RulesIndex | null> {
  assertAllowedRuleUrl(source);
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
    assertAllowedRuleUrl(rule.url);
    const response = await fetch(rule.url);
    if (!response.ok) return false;
    const content = await response.text();
    // SECURITY: content written here is trusted at scan time — its YAML patterns
    // become live regex during scans with no further sanitization. The host
    // allowlist in assertAllowedRuleUrl is therefore the security boundary; only
    // rules from an allowlisted origin ever reach this cache.
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
