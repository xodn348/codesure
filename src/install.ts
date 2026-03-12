import { homedir } from 'os';
import { join } from 'path';
import { readFileSync, writeFileSync, existsSync } from 'fs';
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

function handleJsonClient(client: JsonClient): 'installed' | 'skipped' | 'missing' | 'error' {
  if (!existsSync(client.configPath)) return 'missing';

  try {
    const raw = readFileSync(client.configPath, 'utf8');
    const config = JSON.parse(raw) as Record<string, unknown>;

    if (client.isInstalled(config)) return 'skipped';

    const updated = client.addEntry(config);
    writeFileSync(client.configPath, JSON.stringify(updated, null, 2) + '\n');
    return 'installed';
  } catch {
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
  } catch {
    return 'error';
  }
}

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
}
