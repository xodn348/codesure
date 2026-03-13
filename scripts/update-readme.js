#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';

const pkg = JSON.parse(readFileSync('package.json', 'utf-8'));
const version = pkg.version;

const readme = readFileSync('README.md', 'utf-8');
const marker = '<summary><strong>Changelog</strong></summary>\n\n';
const idx = readme.indexOf(marker);

if (idx === -1) {
  console.error('[update-readme] Changelog <details> block not found in README.md — skipping.');
  process.exit(0);
}

// Skip if this version is already the first entry in the changelog
const afterMarker = readme.slice(idx + marker.length);
if (afterMarker.startsWith(`### ${version}\n`)) {
  console.log(`[update-readme] ${version} already at top of changelog — skipping.`);
  process.exit(0);
}

let commits = '';
try {
  const lastTag = execSync('git describe --tags --abbrev=0', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  commits = execSync(`git log ${lastTag}..HEAD --pretty=format:"- %s"`, { encoding: 'utf-8' }).trim();
} catch {
  commits = execSync('git log --pretty=format:"- %s" -20', { encoding: 'utf-8' }).trim();
}

const entry = `### ${version}\n\n${commits || '- No changes'}\n\n`;

const insertAt = idx + marker.length;
const updated = readme.slice(0, insertAt) + entry + readme.slice(insertAt);
writeFileSync('README.md', updated, 'utf-8');
console.log(`[update-readme] Injected ${version} changelog into README.md`);
