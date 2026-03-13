import type { SecurityRule, Finding } from '../types.js';
import { CodeSureError } from '../errors.js';
import { safeTruncate } from './sanitize.js';

interface CompiledRule {
  rule: SecurityRule;
  pattern: RegExp;
  patternNot?: RegExp;
  confidence: number;
}

function getConfidence(rule: SecurityRule): number {
  const confidence = rule.metadata?.confidence;
  if (confidence === 'high') return 80;
  if (confidence === 'low') return 50;
  return 70;
}

function compileRules(rules: SecurityRule[]): CompiledRule[] {
  const compiled: CompiledRule[] = [];

  for (const rule of rules) {
    try {
      const pattern = new RegExp(rule.pattern, 'gm');
      let patternNot: RegExp | undefined;

      if (rule.pattern_not !== undefined) {
        try {
          patternNot = new RegExp(rule.pattern_not, 'gm');
        } catch (cause) {
          const err = new CodeSureError('REGEX_COMPILE_FAILED', `Invalid pattern_not for rule ${rule.id}`, { context: { ruleId: rule.id }, cause });
          console.warn(err.message, cause);
        }
      }

      compiled.push({
        rule,
        pattern,
        patternNot,
        confidence: getConfidence(rule),
      });
    } catch (cause) {
      const err = new CodeSureError('REGEX_COMPILE_FAILED', `Invalid regex pattern for rule ${rule.id}`, { context: { ruleId: rule.id }, cause });
      console.warn(err.message, cause);
    }
  }

  return compiled;
}

/**
 * Scans source code line-by-line against compiled YAML security rules.
 *
 * @param code - Source code to scan. Returns empty array if empty.
 * @param rules - Security rules to match against (pre-filtered by language).
 * @param filePath - Optional file path attached to each finding's location.
 * @returns Deduplicated findings array, one per rule per line.
 *
 * @example
 * ```ts
 * const rules = loadRules('src/rules/vulnerability');
 * const findings = scanWithRegex(code, filterRulesByLanguage(rules, 'javascript'));
 * ```
 */
function matchRule(compiled: CompiledRule, line: string, lineNumber: number): RegExpExecArray | null {
  try {
    compiled.pattern.lastIndex = 0;
    const match = compiled.pattern.exec(line);
    if (match === null) return null;

    if (compiled.patternNot !== undefined) {
      compiled.patternNot.lastIndex = 0;
      if (compiled.patternNot.test(line)) return null;
    }

    return match;
  } catch (cause) {
    const err = new CodeSureError('REGEX_EXEC_FAILED', `Regex failed for rule ${compiled.rule.id}`, {
      context: { ruleId: compiled.rule.id, lineNumber },
      cause,
    });
    console.warn(err.message, cause);
    return null;
  }
}

function buildFinding(compiled: CompiledRule, match: RegExpExecArray, line: string, lineNumber: number, filePath?: string): Finding {
  return {
    id: `${compiled.rule.id}-L${lineNumber}`,
    severity: compiled.rule.severity,
    category: compiled.rule.category,
    confidence: compiled.confidence,
    rule_id: compiled.rule.id,
    taxonomy: compiled.rule.taxonomy,
    message: compiled.rule.message,
    location: { file: filePath, line: lineNumber, column: match.index },
    snippet: safeTruncate(line.trim(), 200),
    fix_suggestion: compiled.rule.fix,
  };
}

export function scanWithRegex(code: string, rules: SecurityRule[], filePath?: string): Finding[] {
  if (code.length === 0 || rules.length === 0) {
    return [];
  }

  const lines = code.split(/\r?\n/);
  const compiledRules = compileRules(rules);
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    const lineNumber = index + 1;

    for (const compiled of compiledRules) {
      const match = matchRule(compiled, line, lineNumber);
      if (match === null) continue;

      const dedupeKey = `${compiled.rule.id}:${lineNumber}`;
      if (seen.has(dedupeKey)) continue;

      findings.push(buildFinding(compiled, match, line, lineNumber, filePath));
      seen.add(dedupeKey);
    }
  }

  return findings;
}
