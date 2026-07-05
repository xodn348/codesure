import type { Finding } from '../types.js';

/**
 * Maximum number of findings retained in the in-process store.
 * Bounds memory so long-running servers never accumulate findings without limit.
 */
const MAX_FINDINGS = 500;

/**
 * Insertion-ordered map of finding id -> Finding. Oldest entries are evicted
 * first once the store exceeds {@link MAX_FINDINGS}.
 */
const store = new Map<string, Finding>();

/**
 * Records scan findings so they can later be retrieved by id (e.g. for reporting).
 *
 * Re-inserts existing ids to mark them as most-recently-seen, and evicts the
 * oldest entries once the store grows past its bounded capacity.
 *
 * @param findings - Findings produced by a scan; each must have a unique `id`.
 * @returns Nothing; mutates the module-level store as a side effect.
 * @example
 * rememberFindings(result.findings);
 * const f = getFinding(result.findings[0].id);
 */
export function rememberFindings(findings: Finding[]): void {
  for (const finding of findings) {
    if (store.has(finding.id)) store.delete(finding.id);
    store.set(finding.id, finding);
  }
  while (store.size > MAX_FINDINGS) {
    const oldest = store.keys().next().value;
    if (oldest === undefined) break;
    store.delete(oldest);
  }
}

/**
 * Retrieves a previously remembered finding by its id.
 *
 * @param id - The `Finding.id` assigned during a scan.
 * @returns The full {@link Finding}, or `undefined` if unknown or already evicted.
 */
export function getFinding(id: string): Finding | undefined {
  return store.get(id);
}
