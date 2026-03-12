import type { SecurityRule, Finding } from '../types.js';

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
        } catch (error) {
          console.warn(`Invalid regex pattern_not for rule ${rule.id}:`, error);
        }
      }

      compiled.push({
        rule,
        pattern,
        patternNot,
        confidence: getConfidence(rule),
      });
    } catch (error) {
      console.warn(`Invalid regex pattern for rule ${rule.id}:`, error);
    }
  }

  return compiled;
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
      let match: RegExpExecArray | null = null;

      try {
        compiled.pattern.lastIndex = 0;
        match = compiled.pattern.exec(line);
      } catch (error) {
        console.warn(`Regex execution failed for rule ${compiled.rule.id}:`, error);
        continue;
      }

      if (match === null) {
        continue;
      }

      if (compiled.patternNot !== undefined) {
        try {
          compiled.patternNot.lastIndex = 0;
          if (compiled.patternNot.test(line)) {
            continue;
          }
        } catch (error) {
          console.warn(`Regex pattern_not execution failed for rule ${compiled.rule.id}:`, error);
          continue;
        }
      }

      const dedupeKey = `${compiled.rule.id}:${lineNumber}`;
      if (seen.has(dedupeKey)) {
        continue;
      }

      findings.push({
        id: `${compiled.rule.id}-L${lineNumber}`,
        severity: compiled.rule.severity,
        category: compiled.rule.category,
        confidence: compiled.confidence,
        rule_id: compiled.rule.id,
        taxonomy: compiled.rule.taxonomy,
        message: compiled.rule.message,
        location: {
          file: filePath,
          line: lineNumber,
          column: match.index,
        },
        snippet: line.trim().slice(0, 200),
        fix_suggestion: compiled.rule.fix,
      });
      seen.add(dedupeKey);
    }
  }

  return findings;
}
