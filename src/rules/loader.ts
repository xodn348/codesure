import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import yaml from 'js-yaml';
import type { SecurityRule } from '../types.js';

const REQUIRED_FIELDS: (keyof SecurityRule)[] = [
  'id',
  'category',
  'severity',
  'languages',
  'pattern',
  'message',
];

const VALID_CATEGORIES = new Set(['vulnerability', 'malicious']);
const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

const LANG_ALIASES: Record<string, string> = {
  js: 'javascript',
  ts: 'typescript',
  py: 'python',
};

interface RawRule {
  id?: unknown;
  category?: unknown;
  taxonomy?: unknown;
  severity?: unknown;
  languages?: unknown;
  pattern?: unknown;
  'pattern-not'?: unknown;
  pattern_not?: unknown;
  message?: unknown;
  fix?: unknown;
  metadata?: {
    cwe?: unknown;
    owasp?: unknown;
    confidence?: unknown;
  };
}

interface RawYaml {
  rules?: unknown[];
}

function isValidRule(raw: RawRule): raw is RawRule & {
  id: string;
  category: string;
  severity: string;
  languages: string[];
  pattern: string;
  message: string;
} {
  for (const field of REQUIRED_FIELDS) {
    const yamlField = field === 'pattern_not' ? 'pattern-not' : field;
    if (raw[yamlField as keyof RawRule] === undefined && raw[field as keyof RawRule] === undefined) {
      if (field !== 'pattern_not') {
        console.warn(`[codesure] Skipping rule: missing required field "${field}"`);
        return false;
      }
    }
  }

  if (typeof raw.id !== 'string' || raw.id.trim() === '') {
    console.warn('[codesure] Skipping rule: "id" must be a non-empty string');
    return false;
  }

  if (typeof raw.category !== 'string' || !VALID_CATEGORIES.has(raw.category)) {
    console.warn(`[codesure] Skipping rule "${raw.id}": invalid category "${raw.category}"`);
    return false;
  }

  if (typeof raw.severity !== 'string' || !VALID_SEVERITIES.has(raw.severity)) {
    console.warn(`[codesure] Skipping rule "${raw.id}": invalid severity "${raw.severity}"`);
    return false;
  }

  if (!Array.isArray(raw.languages) || raw.languages.length === 0) {
    console.warn(`[codesure] Skipping rule "${raw.id}": "languages" must be a non-empty array`);
    return false;
  }

  if (typeof raw.pattern !== 'string' || raw.pattern.trim() === '') {
    console.warn(`[codesure] Skipping rule "${raw.id}": "pattern" must be a non-empty string`);
    return false;
  }

  if (typeof raw.message !== 'string' || raw.message.trim() === '') {
    console.warn(`[codesure] Skipping rule "${raw.id}": "message" must be a non-empty string`);
    return false;
  }

  return true;
}

function toSecurityRule(raw: RawRule): SecurityRule {
  const patternNot = (raw['pattern-not'] ?? raw.pattern_not) as string | undefined;

  const rule: SecurityRule = {
    id: raw.id as string,
    category: raw.category as SecurityRule['category'],
    severity: raw.severity as SecurityRule['severity'],
    languages: (raw.languages as string[]).map((l) => l.toLowerCase()),
    pattern: raw.pattern as string,
    message: raw.message as string,
  };

  if (raw.taxonomy !== undefined) {
    rule.taxonomy = raw.taxonomy as SecurityRule['taxonomy'];
  }

  if (patternNot !== undefined) {
    rule.pattern_not = patternNot;
  }

  if (raw.fix !== undefined) {
    rule.fix = raw.fix as string;
  }

  if (raw.metadata !== undefined) {
    const meta: NonNullable<SecurityRule['metadata']> = {};
    if (raw.metadata.cwe !== undefined) meta.cwe = raw.metadata.cwe as string;
    if (raw.metadata.owasp !== undefined) meta.owasp = raw.metadata.owasp as string;
    if (raw.metadata.confidence !== undefined) {
      meta.confidence = raw.metadata.confidence as NonNullable<SecurityRule['metadata']>['confidence'];
    }
    rule.metadata = meta;
  }

  return rule;
}

export function parseRuleFile(filePath: string): SecurityRule[] {
  let content: string;
  try {
    content = readFileSync(filePath, 'utf-8');
  } catch (err) {
    console.warn(`[codesure] Could not read rule file "${filePath}": ${err}`);
    return [];
  }

  let parsed: unknown;
  try {
    parsed = yaml.load(content);
  } catch (err) {
    console.warn(`[codesure] Could not parse YAML in "${filePath}": ${err}`);
    return [];
  }

  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    !Array.isArray((parsed as RawYaml).rules)
  ) {
    console.warn(`[codesure] Rule file "${filePath}" must have a top-level "rules" array`);
    return [];
  }

  const rawRules = (parsed as RawYaml).rules as unknown[];
  const valid: SecurityRule[] = [];

  for (const raw of rawRules) {
    if (typeof raw !== 'object' || raw === null) {
      console.warn(`[codesure] Skipping non-object rule entry in "${filePath}"`);
      continue;
    }

    const rawRule = raw as RawRule;
    if (isValidRule(rawRule)) {
      valid.push(toSecurityRule(rawRule));
    }
  }

  return valid;
}

function collectYamlFiles(dir: string): string[] {
  const results: string[] = [];

  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return results;
  }

  for (const entry of entries) {
    const fullPath = join(dir, entry);
    let stat;
    try {
      stat = statSync(fullPath);
    } catch {
      continue;
    }

    if (stat.isDirectory()) {
      results.push(...collectYamlFiles(fullPath));
    } else if (entry.endsWith('.yaml') || entry.endsWith('.yml')) {
      results.push(fullPath);
    }
  }

  return results;
}

export function loadRules(rulesDir: string): SecurityRule[] {
  const files = collectYamlFiles(rulesDir);
  return files.flatMap((file) => parseRuleFile(file));
}

export function filterRulesByLanguage(rules: SecurityRule[], lang: string): SecurityRule[] {
  const normalized = LANG_ALIASES[lang.toLowerCase()] ?? lang.toLowerCase();
  return rules.filter((rule) =>
    rule.languages.some((l) => l.toLowerCase() === normalized),
  );
}
