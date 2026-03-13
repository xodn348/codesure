import { homedir } from 'os';
import { join } from 'path';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { execSync } from 'child_process';

type JsonClient = {
  kind: 'json';
  name: string;
  configPath: string;
  isInstalled: (config: Record<string, unknown>) => boolean;
  addEntry: (config: Record<string, unknown>) => Record<string, unknown>;
};

type CliClient = {
  kind: 'cli';
  name: string;
  checkCmd: string;
  installCmd: string;
  isInstalledCmd: string;
};

type ClientDef = JsonClient | CliClient;

type RuleTarget = {
  name: string;
  path: string;
  content: string;
};

const HOME = homedir();

const clients: ClientDef[] = [
  {
    kind: 'json',
    name: 'Claude Code',
    configPath: join(HOME, '.claude.json'),
    isInstalled: (c) => !!(c.mcpServers as Record<string, unknown>)?.codesure,
    addEntry: (c) => {
      const servers = (c.mcpServers ?? {}) as Record<string, unknown>;
      servers.codesure = { type: 'stdio', command: 'npx', args: ['-y', 'codesure'] };
      c.mcpServers = servers;
      return c;
    },
  },
  {
    kind: 'cli',
    name: 'Codex',
    checkCmd: 'which codex',
    isInstalledCmd: 'codex mcp list 2>/dev/null',
    installCmd: 'codex mcp add codesure -- npx -y codesure',
  },
  {
    kind: 'json',
    name: 'Opencode',
    configPath: join(HOME, '.config/opencode/config.json'),
    isInstalled: (c) => !!(c.mcp as Record<string, unknown>)?.codesure,
    addEntry: (c) => {
      const mcp = (c.mcp ?? {}) as Record<string, unknown>;
      mcp.codesure = { type: 'local', command: ['npx', '-y', 'codesure'], enabled: true };
      c.mcp = mcp;
      return c;
    },
  },
  {
    kind: 'json',
    name: 'Claude Desktop',
    configPath: join(HOME, 'Library/Application Support/Claude/claude_desktop_config.json'),
    isInstalled: (c) => !!(c.mcpServers as Record<string, unknown>)?.codesure,
    addEntry: (c) => {
      const servers = (c.mcpServers ?? {}) as Record<string, unknown>;
      servers.codesure = { command: 'npx', args: ['-y', 'codesure'] };
      c.mcpServers = servers;
      return c;
    },
  },
  {
    kind: 'json',
    name: 'Cursor',
    configPath: join(HOME, '.cursor/mcp.json'),
    isInstalled: (c) => !!(c.mcpServers as Record<string, unknown>)?.codesure,
    addEntry: (c) => {
      const servers = (c.mcpServers ?? {}) as Record<string, unknown>;
      servers.codesure = { command: 'npx', args: ['-y', 'codesure'] };
      c.mcpServers = servers;
      return c;
    },
  },
  {
    kind: 'json',
    name: 'VS Code (Copilot)',
    configPath: join(HOME, 'Library/Application Support/Code/User/settings.json'),
    isInstalled: (c) => !!(c['github.copilot.mcp.servers'] as Record<string, unknown>)?.codesure,
    addEntry: (c) => {
      const servers = ((c['github.copilot.mcp.servers'] ?? {}) as Record<string, unknown>);
      servers.codesure = { command: 'npx', args: ['-y', 'codesure'] };
      c['github.copilot.mcp.servers'] = servers;
      return c;
    },
  },
];

const RULE_CONTENT = [
  'After writing or modifying code, always call the scan_code MCP tool.',
  'If critical findings exist, fix them before returning code to the user.',
  'If high findings exist, return code with a short warning and fix suggestions.',
].join('\n');

const ruleTargets: RuleTarget[] = [
  {
    name: 'Claude Code rule',
    path: join(HOME, '.claude/rules/codesure.md'),
    content: RULE_CONTENT,
  },
  {
    name: 'Codex AGENTS',
    path: join(HOME, '.codex/AGENTS.md'),
    content: RULE_CONTENT,
  },
  {
    name: 'Opencode AGENTS',
    path: join(HOME, '.config/opencode/AGENTS.md'),
    content: RULE_CONTENT,
  },
  {
    name: 'Cursor rules',
    path: join(HOME, '.cursorrules'),
    content: RULE_CONTENT,
  },
];

function ensureParentDirectory(path: string): void {
  const lastSlash = path.lastIndexOf('/');
  if (lastSlash <= 0) {
    return;
  }
  const parent = path.slice(0, lastSlash);
  mkdirSync(parent, { recursive: true });
}

function setupAutoScanRules(): { created: number; skipped: number; failed: number } {
  let created = 0;
  let skipped = 0;
  let failed = 0;

  for (const target of ruleTargets) {
    try {
      if (existsSync(target.path)) {
        const existing = readFileSync(target.path, 'utf8');
        if (existing.includes('scan_code MCP tool')) {
          skipped += 1;
          continue;
        }
        const merged = `${existing.trimEnd()}\n\n${target.content}\n`;
        writeFileSync(target.path, merged, 'utf8');
        created += 1;
        continue;
      }

      ensureParentDirectory(target.path);
      writeFileSync(target.path, `${target.content}\n`, 'utf8');
      created += 1;
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      console.warn(`[codesure install] Failed to write ${target.name} at ${target.path}: ${msg}`);
      failed += 1;
    }
  }

  return { created, skipped, failed };
}

function handleJsonClient(client: JsonClient): 'installed' | 'skipped' | 'missing' | 'error' {
  if (!existsSync(client.configPath)) return 'missing';

  try {
    const raw = readFileSync(client.configPath, 'utf8');
    const config = JSON.parse(raw) as Record<string, unknown>;

    if (client.isInstalled(config)) return 'skipped';

    const freshRaw = readFileSync(client.configPath, 'utf8');
    const freshConfig = JSON.parse(freshRaw) as Record<string, unknown>;
    const updated = client.addEntry(freshConfig);
    writeFileSync(client.configPath, JSON.stringify(updated, null, 2) + '\n', 'utf8');
    return 'installed';
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.warn(`[codesure install] ${client.name} config update failed: ${msg}`);
    return 'error';
  }
}

function handleCliClient(client: CliClient): 'installed' | 'skipped' | 'missing' | 'error' {
  try {
    execSync(client.checkCmd, { stdio: 'ignore' });
  } catch {
    return 'missing';
  }

  try {
    const list = execSync(client.isInstalledCmd, { encoding: 'utf8' });
    if (list.includes('codesure')) return 'skipped';
    execSync(client.installCmd, { stdio: 'ignore' });
    return 'installed';
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.warn(`[codesure install] ${client.name} CLI install failed: ${msg}`);
    return 'error';
  }
}

/**
 * Auto-detects installed AI coding clients and registers codesure as an MCP server.
 *
 * Patches config files for Claude Code, Codex, Opencode, Claude Desktop, Cursor,
 * and VS Code. Already-configured clients are skipped. Also writes auto-scan rules
 * to each client's rule file so AI agents call `scan_code` after code changes.
 *
 * @returns Resolves when all clients have been processed.
 * @throws Never throws — individual client failures are logged and skipped.
 */
export async function install(): Promise<void> {
  console.log('\n🔍 CodeSure — Auto-install MCP\n');

  let installed = 0;
  let skipped = 0;
  let detected = 0;

  for (const client of clients) {
    const result = client.kind === 'json'
      ? handleJsonClient(client)
      : handleCliClient(client);

    if (result === 'missing') continue;

    detected++;
    if (result === 'installed') {
      console.log(`  ✅ ${client.name}: codesure added`);
      installed++;
    } else if (result === 'skipped') {
      console.log(`  ⏭  ${client.name}: already configured`);
      skipped++;
    } else {
      console.log(`  ⚠️  ${client.name}: failed to update config (check file permissions)`);
    }
  }

  const ruleSetup = setupAutoScanRules();

  if (detected === 0) {
    console.log('  ℹ️  No MCP clients detected on this machine.\n');
    console.log('  Manual setup (add to your client config):\n');
    console.log('  Claude Code  → claude mcp add codesure -- npx -y codesure');
    console.log('  Codex        → codex mcp add codesure -- npx -y codesure');
    console.log('  Opencode     → add to ~/.config/opencode/config.json under "mcp"');
    console.log('  Claude Desktop → add to ~/Library/Application Support/Claude/claude_desktop_config.json\n');
  } else {
    console.log(`\n✨ Done! Restart your MCP client to activate CodeSure.\n`);
  }

  console.log('Auto-scan rule setup:');
  console.log(`  ✅ created/updated: ${ruleSetup.created}`);
  console.log(`  ⏭  already present: ${ruleSetup.skipped}`);
  if (ruleSetup.failed > 0) {
    console.log(`  ⚠️  failed: ${ruleSetup.failed}`);
  }
}
