# CodeSure

![privacy-first](https://img.shields.io/badge/privacy--first-100%25-brightgreen)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue)
![MCP stdio](https://img.shields.io/badge/MCP-stdio-blueviolet)
![MIT](https://img.shields.io/badge/License-MIT-yellow)

Privacy-first MCP security scanner for AI-generated code. Runs as a **stdio MCP server** — your AI coding assistant calls it directly via standard input/output. No HTTP, no ports, no network. 100% local execution.

## Install

Run once. CodeSure auto-detects your AI coding tools and registers itself:

```bash
npx -y codesure install
```

```
🔍 CodeSure — Auto-install MCP

  ✅ Claude Code: codesure added
  ✅ Codex: codesure added
  ⏭  Opencode: already configured
  ✅ Claude Desktop: codesure added
  ✅ Cursor: codesure added

✨ Done! Restart your MCP client to activate CodeSure.
```

Restart your client. `scan_code`, `scan_package`, and other tools appear automatically.

**Supported clients**: Claude Code · Codex · Opencode · Claude Desktop · Cursor · VS Code (Copilot)

## How It Works

CodeSure is a **stdio MCP server**. Your AI client spawns it as a child process and communicates via JSON-RPC over stdin/stdout. No HTTP server, no open ports, no network listeners — the process exists only while your client is running.

`npx codesure install` patches your client's config file to register codesure. Clients not installed are silently skipped. Already-configured clients are never overwritten.

| Client | Config patched |
|--------|---------------|
| Claude Code | `~/.claude.json` → `mcpServers` |
| Codex | `codex mcp add codesure` (CLI) |
| Opencode | `~/.config/opencode/config.json` → `mcp` |
| Claude Desktop | `~/Library/.../Claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `settings.json` → `github.copilot.mcp.servers` |

## Detection Pipeline

CodeSure runs a 5-stage analysis pipeline on every `scan_code` call. Each stage catches what the previous one misses, and later stages reduce false positives from earlier ones.

```
Code input
  │
  ├─ Stage 1: Regex Pattern Matching    36 YAML rules (OWASP + malicious)
  ├─ Stage 2: AST Taint Analysis        3-hop source→sink data flow tracking
  ├─ Stage 3: Entropy Analysis          Shannon entropy for secrets/obfuscation
  ├─ Stage 4: Behavioral Chain          Cross-signal confidence boosting
  └─ Stage 5: Context Filter            Path-based FP reduction
```

### Stage 1 — Regex Pattern Matching

Matches each line against 36 rules (16 vulnerability + 20 malicious). Each rule is a YAML file with `pattern` (positive match) and `pattern_not` (negative exclusion). Catches known patterns like `eval()`, `innerHTML`, SQL concatenation, `child_process.exec`, reverse shells, crypto miners.

> **Research basis**: Pattern-based detection remains the foundation of production SAST tools. Semgrep, CodeQL, and ESLint security plugins all use rule-based pattern matching as their primary detection layer.

### Stage 2 — AST Taint Analysis

Tracks data flow from **sources** (`req.query`, `document.cookie`, `process.env`) to **sinks** (`eval()`, `db.query()`, `innerHTML`) through variable assignments, up to 3 hops. Distinguishes `eval("hello")` (safe constant) from `eval(userInput)` (tainted external input).

> **Research basis**: Static taint analysis is the established method for detecting injection vulnerabilities. Almashfi & Lu (2021) demonstrated precise detection of DOM-based XSS via source-to-sink taint tracking in JavaScript. Ghebremichael et al. (2025) showed that combining taint specifications with static analysis detects 106 previously-undetectable vulnerabilities in npm packages.
>
> - Almashfi, N. & Lu, L. (2021). *Static Taint Analysis for JavaScript Programs*. CCIS vol. 1288, pp. 155-167. [DOI: 10.1007/978-3-030-71472-7_13](https://doi.org/10.1007/978-3-030-71472-7_13)
> - Ghebremichael, J. et al. (2025). *SemTaint: Multi-Agent Taint Specification Extraction for Vulnerability Detection*. [arXiv:2601.10865](https://arxiv.org/abs/2601.10865)
> - Dutta, S. et al. (2021). *InspectJS: Leveraging Code Similarity and User-Feedback for Effective Taint Specification Inference for JavaScript*. [arXiv:2111.09625](https://arxiv.org/abs/2111.09625)

### Stage 3 — Entropy Analysis

Computes Shannon entropy of string literals. High-entropy strings (≥ 4.5 bits/byte) in sensitive contexts (`password`, `secret`, `api_key`) are flagged as potential hardcoded secrets or obfuscated payloads. UUIDs, JWTs, hex hashes, base64 images, and version strings are exempted.

> **Research basis**: Lyda & Hamrock (2007) established entropy analysis as an effective technique for identifying encrypted and packed malware. Sujon et al. (2025) validated Shannon entropy as a discriminating feature across file types with ML models. Veracode (2021) demonstrated its application to detecting obfuscated malicious code in JavaScript packages.
>
> - Lyda, R. & Hamrock, J. (2007). *Using Entropy Analysis to Find Encrypted and Packed Malware*. IEEE Security & Privacy, 5(2), 40-45. [DOI: 10.1109/MSP.2007.48](https://doi.org/10.1109/MSP.2007.48)
> - Sujon, K.M. et al. (2025). *A novel framework for malware detection using entropy-based statistical features*. Engineering Research Express, 7(2). [DOI: 10.1088/2631-8695/add645](https://doi.org/10.1088/2631-8695/add645)
> - Veracode. (2021). *Using Entropy to Identify Obfuscated Malicious Code*. [veracode.com](https://www.veracode.com/blog/detecting-obfuscated-malicious-code/)

### Stage 4 — Behavioral Chain Analysis

Groups findings by file using a 7-category taxonomy (EXS/EXM/EXF/NET/SYS/DEF/MET). When multiple categories co-occur in one file — e.g., code execution source (EXS) + execution method (EXM) + data exfiltration (EXF) — confidence is boosted (up to 2x). Individual signals may be benign; combined signals strongly indicate malicious intent.

> **Research basis**: Zhang et al. (2024) demonstrated that modeling malicious behavior as sequences achieves cross-ecosystem detection (npm + PyPI simultaneously). Huang et al. (2024) built a behavioral knowledge base with hierarchical classification for malicious npm packages using API call sequences.
>
> - Zhang, J. et al. (2024). *Killing Two Birds with One Stone: Malicious Package Detection in NPM and PyPI using a Single Model of Malicious Behavior Sequence*. ACM TOSEM, 34(4). [DOI: 10.1145/3705304](https://doi.org/10.1145/3705304)
> - Huang, C. et al. (2024). *DONAPI: Malicious NPM Packages Detector using Behavior Sequence Knowledge Mapping*. USENIX Security. [usenix.org](https://www.usenix.org/conference/usenixsecurity24/presentation/huang-cheng)
> - Gokkaya, B. et al. (2026). *Software supply chain: A taxonomy of attacks, mitigations and risk assessment strategies*. J. Information Security and Applications, 97. [DOI: 10.1016/j.jisa.2025.104324](https://doi.org/10.1016/j.jisa.2025.104324)

### Stage 5 — Context Filter

Adjusts confidence based on file path. Test files (`*.test.ts`, `__tests__/`) get reduced confidence (×0.3). Vendor/generated code (`node_modules/`, `.min.js`) gets zeroed out. Production code stays at full confidence. Prevents false positives from test fixtures and third-party code.

> **Research basis**: Du et al. (2026) showed that hybrid static analysis + context-aware filtering eliminates 94-98% of false positives in industrial codebases (Tencent). Lin (2025) demonstrated that adaptive source-sink identification with context validation reduces FP by 43.7% on average.
>
> - Du, X. et al. (2026). *Reducing False Positives in Static Bug Detection with LLMs: An Empirical Study in Industry*. [arXiv:2601.18844](https://arxiv.org/abs/2601.18844)
> - Lin, S. (2025). *LLM-Driven Adaptive Source-Sink Identification and False Positive Mitigation for Static Analysis*. [arXiv:2511.04023](https://arxiv.org/abs/2511.04023)

## MCP Tools

Once installed, your AI assistant gains these tools:

| Tool | What it does |
|------|-------------|
| `scan_code` | Scans source code through the 5-stage pipeline. Returns findings with severity, confidence, line numbers, and fix suggestions. |
| `scan_package` | Checks npm packages for typosquatting and supply-chain risks before you install them. |
| `scan_manifest` | Audits browser extension and app manifests for dangerous permissions. |
| `report_pattern` | Anonymizes a detected malicious pattern and reports it as a GitHub issue to the community rules repo. Requires explicit user confirmation. |
| `update_rules` | Downloads the latest community detection rules. |

## What It Detects

**Vulnerabilities** — SQL injection, XSS, eval injection, hardcoded secrets, CSRF, path traversal, prototype pollution, insecure random, command injection

**Malicious code** — Data exfiltration (DNS/HTTP), obfuscation, reverse shells, crypto miners, keyloggers, malicious install scripts, suspicious domains

## Privacy & Data Policy

**Your code never leaves your machine. Your prompts are never collected.**

- **stdio MCP**: CodeSure runs as a child process of your AI client, communicating only via stdin/stdout. No HTTP server, no open ports, no network listeners during scanning.
- **Zero telemetry**: No usage statistics, no scan results, no prompts, no user information is collected or transmitted. Ever.
- **No prompt access**: CodeSure receives only the `code` string passed to `scan_code`. It has no access to your conversation history, prompts, or any other context from your AI client.
- **Bug reports only**: The `report_pattern` tool sends only anonymized pattern metadata (rule ID, taxonomy category, confidence score) as a GitHub issue to the community rules repo. It contains zero source code, zero user information, and runs only when you explicitly confirm. This is the only network call CodeSure ever makes.

## Accuracy

Benchmarked on 60+ test fixtures (development 70% / holdout 30%):

| Metric | Dev Set | Holdout Set |
|--------|---------|-------------|
| Youden Index | 0.854 | 0.917 |
| True Positive Rate | > 90% | > 90% |
| False Positive Rate | < 10% | < 10% |

## V1 Limitations

- Taint analysis is limited to 3-hop AST (single file); cross-file taint is not tracked
- Tier 3-6 obfuscation (control flow flattening, virtualization) may not be detected

## License

MIT
