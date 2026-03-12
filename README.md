# CodeSure

![privacy-first](https://img.shields.io/badge/privacy--first-100%25-brightgreen)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue)
![MIT](https://img.shields.io/badge/License-MIT-yellow)

Privacy-first MCP security scanner. Detects vulnerabilities and malicious code in AI-generated code. 100% local — your code never leaves your machine.

## Quick Start

```bash
npx codesure
```

## Configuration

### Claude Code
Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "codesure": {
      "command": "npx",
      "args": ["codesure"],
      "env": {
        "GITHUB_TOKEN": "your_github_token_here"
      }
    }
  }
}
```

### Cursor
Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "codesure": {
      "command": "npx",
      "args": ["codesure"]
    }
  }
}
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `scan_code` | Scan source code for security vulnerabilities and malicious patterns. Runs 100% locally. |
| `scan_package` | Check an npm package name against registry for existence, typosquatting, and supply-chain risks. |
| `scan_manifest` | Check a browser extension or app manifest for dangerous permissions and CSP issues. |
| `report_pattern` | Anonymize and report a detected malicious pattern to the community rules repo. |
| `update_rules` | Download and merge the latest community detection rules. |

## Detection Categories

- **Vulnerability**: SQL injection, XSS, eval injection, hardcoded secrets, CSRF, path traversal, prototype pollution, insecure random.
- **Malicious**: Data exfiltration (DNS/Post), obfuscation detection, reverse shells, crypto miners, keyloggers, suspicious domain connections, malicious install scripts.

## Privacy Statement

**100% Local Execution.** CodeSure is designed with a "local-first" philosophy. Your source code never leaves your machine during a scan.
- **Zero Telemetry**: We do not collect usage statistics or scan results.
- **Explicit Reporting**: The `report_pattern` tool only sends anonymized metadata and only when explicitly confirmed by the user.

## V1 Limitations

- **Obfuscation**: Tier 3-6 advanced obfuscation (e.g. control flow flattening, virtualization) may not be fully detected.
- **Taint Analysis**: Currently limited to 3-hop AST taint; deep interprocedural taint across multiple files is not tracked.

## License

MIT
