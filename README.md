# CodeSure

![privacy-first](https://img.shields.io/badge/privacy--first-100%25-brightgreen)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue)
![MIT](https://img.shields.io/badge/License-MIT-yellow)

Privacy-first MCP security scanner. Detects vulnerabilities and malicious code in AI-generated code. 100% local — your code never leaves your machine.

## Install

Run once. CodeSure auto-detects your AI coding tools and registers itself:

```bash
npx codesure install
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

Restart your client. `scan_code`, `scan_package`, and other tools will appear automatically.

**Supported clients**: Claude Code · Codex · Opencode · Claude Desktop · Cursor · VS Code (Copilot)

## How It Works

`npx codesure install` scans for known MCP client config files on your machine. For each client found, it patches the config to register codesure as an MCP server. Clients not installed are silently skipped. Already-configured clients are never overwritten.

| Client | Config patched |
|--------|---------------|
| Claude Code | `~/.claude.json` → `mcpServers` |
| Codex | `codex mcp add codesure` (CLI) |
| Opencode | `~/.config/opencode/config.json` → `mcp` |
| Claude Desktop | `~/Library/.../Claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `settings.json` → `github.copilot.mcp.servers` |

## MCP Tools

Once installed, your AI assistant gains these tools:

| Tool | What it does |
|------|-------------|
| `scan_code` | Scans source code for vulnerabilities and malicious patterns. 5-stage pipeline: Regex → AST taint → Entropy → Behavioral chain → Context filter. |
| `scan_package` | Checks npm packages for typosquatting and supply-chain risks before you install them. |
| `scan_manifest` | Audits browser extension and app manifests for dangerous permissions. |
| `report_pattern` | Anonymizes and reports a malicious pattern to the community rules repo (requires confirmation). |
| `update_rules` | Downloads the latest community detection rules. |

## What It Detects

**Vulnerabilities** — SQL injection, XSS, eval injection, hardcoded secrets, CSRF, path traversal, prototype pollution, insecure random

**Malicious code** — Data exfiltration (DNS/HTTP), obfuscation, reverse shells, crypto miners, keyloggers, malicious install scripts, suspicious domains

## Privacy

**Your code never leaves your machine.**

- All scanning runs locally — no network calls during analysis
- Zero telemetry — no usage stats, no scan results collected
- `report_pattern` only sends anonymized pattern metadata, and only when you explicitly confirm

## V1 Limitations

- Taint analysis is limited to 3-hop AST (single file); cross-file taint is not tracked
- Tier 3-6 obfuscation (control flow flattening, virtualization) may not be detected

## License

MIT
