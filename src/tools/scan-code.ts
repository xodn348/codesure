import { join, dirname, extname } from 'path';
import { fileURLToPath } from 'url';
import { homedir } from 'os';
import { loadRules, filterRulesByLanguage } from '../rules/loader.js';
import { scanWithRegex } from '../engine/regex-engine.js';
import { scanWithAST } from '../engine/ast-engine.js';
import { scanEntropy } from '../engine/entropy-engine.js';
import { analyzeChain } from '../engine/chain-engine.js';
import { getPathContext, applyContextFilter } from '../engine/context-filter.js';
import { applySuppression } from '../engine/suppression.js';
import { loadCodesureignore, isIgnored, isIgnoredByDefault } from '../engine/codesureignore.js';
import type { ScanResult, Finding, ScanSummary } from '../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// Rules live in src/rules/ (included in npm package via "files").
// Works from both src/tools/ (bun test) and dist/tools/ (node / npx):
//   src/tools/../../src/rules  → src/rules  ✓
//   dist/tools/../../src/rules → src/rules  ✓
const RULES_DIR = join(__dirname, '..', '..', 'src', 'rules');

function getLanguageFromExtension(filePath?: string): string | undefined {
  if (filePath === undefined || filePath.trim() === '') {
    return undefined;
  }

  const extension = extname(filePath).toLowerCase();
  if (extension === '.js' || extension === '.jsx') return 'javascript';
  if (extension === '.ts' || extension === '.tsx') return 'typescript';
  if (extension === '.py') return 'python';

  return undefined;
}

export function detectLanguage(code: string, filePath?: string): string {
  const fromExtension = getLanguageFromExtension(filePath);
  if (fromExtension !== undefined) {
    return fromExtension;
  }

  if (/(?:^|\n)\s*(?:const|let|var)\s+/m.test(code)) {
    return 'javascript';
  }

  if (/(?:^|\n)\s*import\s+.+\s+from\s+.+/m.test(code) || /(?:^|\n)\s*from\s+\S+\s+import\s+/m.test(code)) {
    return 'python';
  }

  return 'javascript';
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const deduped = new Map<string, Finding>();

  for (const finding of findings) {
    const key = `${finding.location.file ?? ''}:${finding.rule_id}:${finding.location.line ?? -1}`;
    const existing = deduped.get(key);
    if (existing === undefined || finding.confidence > existing.confidence) {
      deduped.set(key, finding);
    }
  }

  const uniqueFindings = [...deduped.values()];
  return uniqueFindings.filter((finding) => {
    if (finding.rule_id !== 'ast.taint.source-to-sink') {
      return true;
    }

    return !uniqueFindings.some((otherFinding) =>
      otherFinding !== finding &&
      otherFinding.location.file === finding.location.file &&
      otherFinding.location.line === finding.location.line &&
      otherFinding.category === finding.category,
    );
  });
}

function buildSummary(findings: Finding[], startTime: number): ScanSummary {
  return {
    total: findings.length,
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    info: findings.filter((f) => f.severity === 'info').length,
    suppressed_count: findings.filter((f) => f.suppressed).length,
    scan_time_ms: Date.now() - startTime,
  };
}

function emptyResult(startTime: number): ScanResult {
  const findings: Finding[] = [];
  return {
    findings,
    summary: buildSummary(findings, startTime),
  };
}

/**
 * Runs the full 5-stage security scan pipeline on source code.
 *
 * Stages: regex pattern matching → AST taint analysis → entropy analysis →
 * behavioral chain analysis → context filtering + suppression.
 *
 * @param code - Source code string to scan. Empty string returns zero findings.
 * @param language - Language override (e.g. `"javascript"`). Auto-detected from `filePath` or code heuristics if omitted.
 * @param filePath - Optional file path for context filtering (test files get reduced confidence, vendor files get zeroed).
 * @returns Scan result with deduplicated findings array and severity summary.
 * @throws Never throws — errors in individual stages are caught and skipped.
 *
 * @example
 * ```ts
 * const result = await scanCode('eval(userInput)', 'javascript', 'src/app.ts');
 * console.log(result.summary.critical); // number of critical findings
 * ```
 */
export async function scanCode(
  code: string,
  language?: string,
  filePath?: string,
): Promise<ScanResult> {
  const startTime = Date.now();
  const normalizedLanguage = (language ?? detectLanguage(code, filePath)).toLowerCase();

  const vulnerabilityRules = loadRules(join(RULES_DIR, 'vulnerability'));
  const maliciousRules = loadRules(join(RULES_DIR, 'malicious'));
  const communityRulesDir = join(homedir(), '.codesure', 'community-rules');
  const communityRules = loadRules(communityRulesDir);
  const allRules = [...vulnerabilityRules, ...maliciousRules, ...communityRules];
  const filteredRules = filterRulesByLanguage(allRules, normalizedLanguage);

  const regexFindings = scanWithRegex(code, filteredRules, filePath);
  const astFindings = scanWithAST(code, normalizedLanguage, filePath);
  let findings = dedupeFindings([...regexFindings, ...astFindings]);

  const entropyFindings = scanEntropy(code, normalizedLanguage);
  findings = dedupeFindings([...findings, ...entropyFindings]);
  findings = analyzeChain(findings);

  if (filePath !== undefined && filePath.trim() !== '') {
    const ignorePatterns = loadCodesureignore(process.cwd());
    const pathContext = getPathContext(filePath);
    findings = applyContextFilter(findings, pathContext);
    if (isIgnoredByDefault(filePath) || isIgnored(filePath, ignorePatterns)) {
      findings = findings.map(f => ({ ...f, confidence: 0 }));
    }
  }

  findings = applySuppression(findings, code);

  return {
    findings,
    summary: buildSummary(findings, startTime),
  };
}
