import { describe, test, expect } from 'bun:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isIgnoredByDefault, loadCodesureignore, isIgnored } from './codesureignore.js';

describe('isIgnoredByDefault', () => {
  test('matches default directory patterns', () => {
    expect(isIgnoredByDefault('node_modules/pkg/index.js')).toBe(true);
    expect(isIgnoredByDefault('dist/app.js')).toBe(true);
    expect(isIgnoredByDefault('src/app.ts')).toBe(false);
  });

  test('matches default suffix patterns', () => {
    expect(isIgnoredByDefault('src/app.min.js')).toBe(true);
    expect(isIgnoredByDefault('src/types.d.ts')).toBe(true);
    expect(isIgnoredByDefault('src/app.ts')).toBe(false);
  });
});

describe('loadCodesureignore', () => {
  test('returns defaults when file is missing', () => {
    const dir = mkdtempSync(join(tmpdir(), 'codesureignore-missing-'));
    expect(loadCodesureignore(dir)).toEqual(['node_modules', 'vendor', 'dist', 'build', '.min.js', '.d.ts']);
  });

  test('appends file patterns to defaults', () => {
    const dir = mkdtempSync(join(tmpdir(), 'codesureignore-load-'));
    writeFileSync(join(dir, '.codesureignore'), `coverage
custom-output
`);
    expect(loadCodesureignore(dir)).toEqual(['node_modules', 'vendor', 'dist', 'build', '.min.js', '.d.ts', 'coverage', 'custom-output']);
  });

  test('ignores blank lines and comments', () => {
    const dir = mkdtempSync(join(tmpdir(), 'codesureignore-comments-'));
    writeFileSync(join(dir, '.codesureignore'), `# comment

coverage
`);
    expect(loadCodesureignore(dir)).toEqual(['node_modules', 'vendor', 'dist', 'build', '.min.js', '.d.ts', 'coverage']);
  });
});

describe('isIgnored', () => {
  test('matches simple directory includes', () => {
    expect(isIgnored('vendor/lib/index.js', ['vendor'])).toBe(true);
    expect(isIgnored('src/lib/index.js', ['vendor'])).toBe(false);
  });

  test('matches suffix patterns with includes logic', () => {
    expect(isIgnored('src/file.min.js', ['.min.js'])).toBe(true);
    expect(isIgnored('src/file.d.ts', ['.d.ts'])).toBe(true);
    expect(isIgnored('src/file.ts', ['.d.ts'])).toBe(false);
  });
});
