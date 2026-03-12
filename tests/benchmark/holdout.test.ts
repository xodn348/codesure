import { describe, expect, it } from 'bun:test';
import { join } from 'path';
import { runBenchmark } from './scoring.js';

describe('holdout benchmark', () => {
  it('meets holdout Youden target', async () => {
    const fixtureDir = join(process.cwd(), 'tests/fixtures/holdout');
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
      },
    ]);

    expect(result.youden).toBeGreaterThanOrEqual(0.80);
  });
});
