import { describe, expect, it } from 'bun:test';
import { join } from 'path';
import { runBenchmark } from './scoring.js';

describe('development benchmark', () => {
  it('meets V1 Youden/TPR/FPR targets', async () => {
    const fixtureDir = join(process.cwd(), 'tests/fixtures/development');
    const result = await runBenchmark(fixtureDir);

    console.table([
      {
        category: 'combined',
        TP: result.tp,
        FN: result.fn,
        TN: result.tn,
        FP: result.fp,
        TPR: Number(result.tpr.toFixed(3)),
        FPR: Number(result.fpr.toFixed(3)),
        Youden: Number(result.youden.toFixed(3)),
        Precision: Number(result.precision.toFixed(3)),
        F1: Number(result.f1.toFixed(3)),
      },
      ...Object.entries(result.categories).map(([category, metrics]) => ({
        category,
        TP: metrics.tp,
        FN: metrics.fn,
        TN: metrics.tn,
        FP: metrics.fp,
        TPR: Number(metrics.tpr.toFixed(3)),
        FPR: Number(metrics.fpr.toFixed(3)),
        Youden: Number(metrics.youden.toFixed(3)),
        Precision: Number(metrics.precision.toFixed(3)),
        F1: Number(metrics.f1.toFixed(3)),
      })),
    ]);

    expect(result.youden).toBeGreaterThanOrEqual(0.80);
    expect(result.tpr).toBeGreaterThan(0.85);
    expect(result.fpr).toBeLessThan(0.15);
  });
});
