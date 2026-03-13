#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scanCode } from "./tools/scan-code.js";
import { scanManifest } from "./tools/scan-manifest.js";
import { reportPattern } from "./tools/report-pattern.js";
import { updateRules } from "./tools/update-rules.js";
import { checkPackage } from "./tools/scan-package.js";
import type { AgentInfo } from "./types.js";
import { safeJsonStringify } from "./engine/sanitize.js";

if (process.argv.includes('--version')) {
  const { createRequire } = await import('module');
  const require = createRequire(import.meta.url);
  const pkg = require('../package.json');
  process.stdout.write(pkg.version + '\n');
  process.exit(0);
}

if (process.argv[2] === 'install') {
  const { install } = await import('./install.js');
  await install();
  process.exit(0);
}

const agentInfo: AgentInfo = {
  name: process.env.CODESURE_CLIENT_NAME ?? 'Claude Code',
  version: process.env.CODESURE_CLIENT_VERSION ?? '1.0.0',
};

const server = new McpServer({
  name: "codesure",
  version: "1.0.0",
});

server.registerTool(
  "scan_code",
  {
    description: "Scan source code for security vulnerabilities and malicious patterns. Runs 100% locally — code never leaves your machine.",
    inputSchema: {
      code: z.string().describe("Source code to scan"),
      language: z.string().optional().describe("Programming language (js, ts, python)"),
      file_path: z.string().optional().describe("File path for context-aware filtering"),
    },
  },
  async ({ code, language, file_path }) => {
    const result = await scanCode(code, language, file_path);
    return {
      content: [{ type: "text" as const, text: safeJsonStringify(result, 2) }],
    };
  }
);

server.registerTool(
  "scan_package",
  {
    description: "Check an npm package name against registry for existence, typosquatting, and supply-chain risks.",
    inputSchema: {
      name: z.string().describe("Package name to check"),
    },
  },
  async ({ name }) => {
    const result = await checkPackage(name);
    return {
      content: [{ type: "text" as const, text: safeJsonStringify(result, 2) }],
    };
  }
);

server.registerTool(
  "scan_manifest",
  {
    description: "Check a browser extension or app manifest for dangerous permissions and CSP issues.",
    inputSchema: {
      manifest_content: z.string().describe("JSON manifest content as a string"),
      type: z.enum(["chrome_extension", "vscode_extension", "package_json"]).optional().describe("Manifest type"),
    },
  },
  async ({ manifest_content, type }) => {
    const result = scanManifest(manifest_content, type);
    return {
      content: [{ type: "text" as const, text: safeJsonStringify(result, 2) }],
    };
  }
);

server.registerTool(
  "report_pattern",
  {
    description: "Anonymize and report a detected malicious pattern to the CodeSure community rules repo (requires GITHUB_TOKEN).",
    inputSchema: {
      finding_id: z.string().describe("ID of the finding to report"),
      confirm: z.boolean().describe("User confirmed they want to submit this pattern"),
    },
  },
  async ({ finding_id, confirm }) => {
    if (!confirm) {
      return {
        content: [{ type: "text" as const, text: "Confirmation required. Set confirm: true to report this pattern." }],
      };
    }
    const stubFinding = {
      id: finding_id,
      severity: "medium" as const,
      category: "vulnerability" as const,
      confidence: 0,
      rule_id: finding_id,
      message: "Stub finding for pattern reporting",
      location: {},
    };
    const result = await reportPattern(stubFinding, agentInfo);
    return {
      content: [{ type: "text" as const, text: result.message + (result.url ? `\nIssue: ${result.url}` : "") }],
    };
  }
);

server.registerTool(
  "update_rules",
  {
    description: "Download and merge the latest community detection rules from the CodeSure rules repository.",
    inputSchema: {
      source: z.string().optional().describe("Custom rules repository URL (default: xodn348/codesure-rules)"),
    },
  },
  async ({ source }) => {
    const result = await updateRules(source);
    return {
      content: [{ type: "text" as const, text: `${result.message} (${result.updated} rule(s) updated)` }],
    };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
process.stderr.write("CodeSure MCP server started\n");
