import { readdir, readFile, writeFile } from 'fs/promises';
import { join, relative } from 'path';
import { parseAnnotations } from './annotation-parser.js';
import { scanCode } from '../../src/tools/scan-code.js';

interface BenchmarkCounts {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
}

export interface BenchmarkMetrics extends BenchmarkCounts {
  tpr: number;
  fpr: number;
  youden: number;
  precision: number;
  f1: number;
}

export interface BenchmarkResult extends BenchmarkMetrics {
  fixtureDir: string;
  scannedFiles: number;
  categories: Record<string, BenchmarkMetrics>;
}

const SUPPORTED_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.py']);

function safeDivide(numerator: number, denominator: number): number {
  return denominator === 0 ? 0 : numerator / denominator;
}

function withMetrics(counts: BenchmarkCounts): BenchmarkMetrics {
  const tpr = safeDivide(counts.tp, counts.tp + counts.fn);
  const fpr = safeDivide(counts.fp, counts.fp + counts.tn);
  const precision = safeDivide(counts.tp, counts.tp + counts.fp);
  const f1 = safeDivide(2 * precision * tpr, precision + tpr);

  return {
    ...counts,
    tpr,
    fpr,
    youden: tpr - fpr,
    precision,
    f1,
  };
}

function categoryFromFilePath(fixtureDir: string, filePath: string): string {
  const relativePath = relative(fixtureDir, filePath);
  const firstSegment = relativePath.split('/')[0];
  return firstSegment || 'unknown';
}

async function listFixtureFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const all = await Promise.all(
    entries.map(async (entry) => {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        return listFixtureFiles(fullPath);
      }
      const extension = entry.name.slice(entry.name.lastIndexOf('.'));
      if (SUPPORTED_EXTENSIONS.has(extension)) {
        return [fullPath];
      }
      return [];
    }),
  );

  return all.flat();
}

function formatDecimal(value: number): string {
  return value.toFixed(3);
}

function markdownRow(category: string, metrics: BenchmarkMetrics): string {
  return `| ${category} | ${metrics.tp} | ${metrics.fn} | ${metrics.tn} | ${metrics.fp} | ${formatDecimal(metrics.tpr)} | ${formatDecimal(metrics.fpr)} | ${formatDecimal(metrics.youden)} |`;
}

async function writeBenchmarkMarkdown(result: BenchmarkResult): Promise<void> {
  const categoryNames = Object.keys(result.categories).sort();
  const categoryRows = categoryNames.map((name) => markdownRow(name, result.categories[name]));

  const markdown = [
    '# CodeSure Benchmark Results',
    '',
    `- Fixture Directory: \`${result.fixtureDir}\``,
    `- Scanned Files: ${result.scannedFiles}`,
    '',
    '| Category | TP | FN | TN | FP | TPR | FPR | Youden |',
    '|----------|----|----|----|----|-----|-----|--------|',
    ...categoryRows,
    markdownRow('combined', result),
    '',
    `- Precision: ${formatDecimal(result.precision)}`,
    `- F1: ${formatDecimal(result.f1)}`,
  ].join('\n');

  await writeFile(join(process.cwd(), 'BENCHMARK.md'), `${markdown}\n`, 'utf8');
}

export async function runBenchmark(fixtureDir: string): Promise<BenchmarkResult> {
  const fixtureFiles = await listFixtureFiles(fixtureDir);
  const totalCounts: BenchmarkCounts = { tp: 0, fp: 0, fn: 0, tn: 0 };
  const categoryCounts = new Map<string, BenchmarkCounts>();

  for (const fixturePath of fixtureFiles) {
    const code = await readFile(fixturePath, 'utf8');
    const annotations = parseAnnotations(code);

    if (annotations.length === 0) {
      continue;
    }

    const hasPositiveAnnotation = annotations.some((annotation) => annotation.type === 'VULN' || annotation.type === 'MALICIOUS');
    const safeOnly = annotations.every((annotation) => annotation.type === 'SAFE');

    if (!hasPositiveAnnotation && !safeOnly) {
      continue;
    }

    const scanResult = await scanCode(code, undefined, fixturePath);
    const hasFinding = scanResult.findings.length > 0;

    const category = categoryFromFilePath(fixtureDir, fixturePath);
    if (!categoryCounts.has(category)) {
      categoryCounts.set(category, { tp: 0, fp: 0, fn: 0, tn: 0 });
    }

    const counts = categoryCounts.get(category)!;

    if (hasPositiveAnnotation) {
      if (hasFinding) {
        totalCounts.tp += 1;
        counts.tp += 1;
      } else {
        totalCounts.fn += 1;
        counts.fn += 1;
      }
      continue;
    }

    if (hasFinding) {
      totalCounts.fp += 1;
      counts.fp += 1;
    } else {
      totalCounts.tn += 1;
      counts.tn += 1;
    }
  }

  const categories: Record<string, BenchmarkMetrics> = {};
  for (const [name, counts] of categoryCounts.entries()) {
    categories[name] = withMetrics(counts);
  }

  const result: BenchmarkResult = {
    fixtureDir,
    scannedFiles: fixtureFiles.length,
    ...withMetrics(totalCounts),
    categories,
  };

  await writeBenchmarkMarkdown(result);
  return result;
}
