import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const DEFAULT_PATTERNS = ['node_modules', 'vendor', 'dist', 'build', '.min.js', '.d.ts'];

function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, '/').replace(/^\.\//, '');
}

function uniquePatterns(patterns: string[]): string[] {
  return [...new Set(patterns.map((pattern) => pattern.trim()).filter(Boolean))];
}

export function isIgnoredByDefault(filePath: string): boolean {
  return isIgnored(filePath, DEFAULT_PATTERNS);
}

export function loadCodesureignore(dir: string): string[] {
  const ignoreFile = join(dir, '.codesureignore');
  if (!existsSync(ignoreFile)) {
    return [...DEFAULT_PATTERNS];
  }

  const filePatterns = readFileSync(ignoreFile, 'utf-8')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'));

  return uniquePatterns([...DEFAULT_PATTERNS, ...filePatterns]);
}

export function isIgnored(filePath: string, patterns: string[]): boolean {
  const normalizedPath = normalizePath(filePath);
  const pathSegments = normalizedPath.split('/').filter(Boolean);

  return patterns.some((pattern) => {
    const normalizedPattern = normalizePath(pattern)
      .replace(/^\*\./, '.')
      .replace(/\/$/, '');
    if (normalizedPattern === '') {
      return false;
    }

    if (normalizedPattern.startsWith('.')) {
      return normalizedPath.endsWith(normalizedPattern);
    }

    if (normalizedPattern.includes('/')) {
      return normalizedPath.includes(normalizedPattern);
    }

    return pathSegments.includes(normalizedPattern);
  });
}
