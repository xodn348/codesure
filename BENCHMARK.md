# CodeSure Benchmark Results

- Fixture Directory: `/Users/jnnj92/codesure/tests/fixtures/development`
- Scanned Files: 41

| Category | TP | FN | TN | FP | TPR | FPR | Youden |
|----------|----|----|----|----|-----|-----|--------|
| benign | 0 | 0 | 13 | 1 | 0.000 | 0.071 | -0.071 |
| malicious | 13 | 0 | 0 | 0 | 1.000 | 0.000 | 1.000 |
| vulnerable | 12 | 2 | 0 | 0 | 0.857 | 0.000 | 0.857 |
| combined | 25 | 2 | 13 | 1 | 0.926 | 0.071 | 0.854 |

- Precision: 0.962
- F1: 0.943
