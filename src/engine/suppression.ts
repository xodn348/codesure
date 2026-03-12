import type { Finding } from '../types.js';

export interface Suppression {
  ruleIds: string[] | null;
  line: number;
}

const SUPPRESS_RE = /(?:\/\/|#)\s*codesure-ignore(?::\s*(.+))?/i;

export function parseSuppression(line: string, lineNumber: number): Suppression | null {
  const match = SUPPRESS_RE.exec(line);
  if (!match) return null;
  const ruleStr = match[1]?.trim();
  const ruleIds = ruleStr
    ? ruleStr.split(',').map((r) => r.trim()).filter(Boolean)
    : null;
  return { ruleIds, line: lineNumber };
}

export function applySuppression(findings: Finding[], code: string): Finding[] {
  const lines = code.split('\n');
  const suppressions = new Map<number, Suppression>();

  lines.forEach((line, idx) => {
    const sup = parseSuppression(line, idx + 1);
    if (sup) suppressions.set(idx + 1, sup);
  });

  return findings.map((f) => {
    const findingLine = f.location.line;
    if (findingLine === undefined) return f;

    const sup = suppressions.get(findingLine) ?? suppressions.get(findingLine - 1);
    if (!sup) return f;

    const matches =
      sup.ruleIds === null ||
      sup.ruleIds.includes(f.rule_id) ||
      sup.ruleIds.includes(f.rule_id.split('.').pop() ?? '');
    if (!matches) return f;

    return {
      ...f,
      suppressed: true,
      suppression_rule: sup.ruleIds?.join(',') ?? 'all',
    };
  });
}
