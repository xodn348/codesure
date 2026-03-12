# Privacy Policy

CodeSure is built on a "Privacy by Design" principle. We believe that security tools should not compromise the privacy of the code they are protecting.

## Technical Guarantees

### Local-Only Code Scanning
The `scan_code` tool is executed entirely on your local machine. It performs regex-based and AST-based analysis without making any external network requests. Your source code never leaves your local environment.

### Limited and Intentional Network Calls
Network access is strictly limited to the following tools and purposes:

1. **`scan_package`**: Sends only the **package name** to `registry.npmjs.org` and `api.npmjs.org` to check for supply-chain risks. It never sends your project's code or dependency list.
2. **`update_rules`**: Downloads latest detection rules from GitHub (`github.com`). This is triggered only by explicit user action.
3. **`report_pattern`**: Reports anonymized pattern metadata to the CodeSure community repo. This requires a `GITHUB_TOKEN` and **explicit user confirmation** for each report.

## What `report_pattern` Sends

When you choose to report a malicious pattern, the following data is transmitted:
- **Taxonomy**: Abstract classification (e.g., `EXM`, `NET`).
- **Language**: Programming language detected (e.g., `javascript`).
- **Confidence**: Numerical confidence score of the detection.
- **Pattern Description**: An abstract identifier derived from the rule ID (e.g., `eval_injection` instead of the actual code).
- **Indicators**: A list of abstract evidence tokens.
- **Agent Info**: Name and version of the AI agent using CodeSure (e.g., `Claude Code 1.0.0`).
- **Timestamp**: Time of the report.

**We NEVER send:**
- Source code snippets
- Local file paths
- Variable names
- Developer names or environment details

## How to Verify Locally

You can audit the source code yourself to verify these privacy claims. For example, you can search for all `fetch` calls in the codebase:

```bash
grep -r "fetch(" src/
```

You will find that `fetch` is only used in:
- `src/tools/scan-package.ts` (NPM registry)
- `src/tools/update-rules.ts` (GitHub rules download)
- `src/tools/report-pattern.ts` (GitHub issue creation)

The core scanning engine (`src/engine/`) has **zero** network dependencies.
