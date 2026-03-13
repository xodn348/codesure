import type { Finding } from '../types.js';
import {
  SENSITIVE_VAR_NAMES,
  ENTROPY_THRESHOLD_SUSPICIOUS,
  ENTROPY_THRESHOLD_HIGH,
} from '../constants.js';
import { safeTruncate } from './sanitize.js';

const EXEMPT_PATTERNS = [
  /[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}/i,
  /^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/,
  /^data:image\/[a-z+]+;base64,/i,
  /^\$2[abxy]\$\d{2}\$/,
  /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i,
  /^#[0-9a-fA-F]{3,8}$/,
  /^v?\d+\.\d+\.\d+/,
  /^\{[^}]+\}$|^\$\{[^}]+\}$/,
];

const STRING_LITERAL_REGEX = /["'`][^"'`\n]{16,}["'`]/g;

export function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;

  const frequencyByCharacter = new Map<string, number>();
  for (const character of str) {
    frequencyByCharacter.set(character, (frequencyByCharacter.get(character) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencyByCharacter.values()) {
    const probability = count / str.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

export function isExemptString(str: string): boolean {
  return EXEMPT_PATTERNS.some((pattern) => pattern.test(str));
}

export function isSensitiveContext(line: string): boolean {
  const normalizedLine = line.toLowerCase();
  return SENSITIVE_VAR_NAMES.some((sensitiveName) => normalizedLine.includes(sensitiveName.toLowerCase()));
}

export function scanEntropy(code: string, filePath?: string): Finding[] {
  if (code.length === 0) {
    return [];
  }

  const findings: Finding[] = [];
  const lines = code.split(/\r?\n/);

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    const lineNumber = index + 1;
    const stringLiterals = line.matchAll(STRING_LITERAL_REGEX);

    for (const literalMatch of stringLiterals) {
      const quotedLiteral = literalMatch[0] ?? '';
      if (quotedLiteral.length < 2) {
        continue;
      }

      const unquotedLiteral = quotedLiteral.slice(1, -1);
      if (isExemptString(unquotedLiteral)) {
        continue;
      }

      const entropy = calculateEntropy(unquotedLiteral);
      if (entropy < ENTROPY_THRESHOLD_SUSPICIOUS) {
        continue;
      }

      if (!isSensitiveContext(line)) {
        continue;
      }

      const isHighEntropy = entropy >= ENTROPY_THRESHOLD_HIGH;
      findings.push({
        id: `entropy-L${lineNumber}-C${literalMatch.index ?? 0}`,
        severity: isHighEntropy ? 'high' : 'medium',
        category: 'malicious',
        confidence: isHighEntropy ? 80 : 55,
        rule_id: 'entropy.high-entropy-string',
        message: `High-entropy string (${entropy.toFixed(2)} bits/byte) in sensitive context — possible obfuscation or hardcoded secret`,
        location: {
          file: filePath,
          line: lineNumber,
          column: literalMatch.index,
        },
        snippet: safeTruncate(line.trim(), 200),
        entropy,
      });
    }
  }

  return findings;
}
