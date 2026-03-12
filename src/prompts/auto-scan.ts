export const SYSTEM_PROMPT = `
SECURITY POLICY: After generating or modifying ANY code, ALWAYS call the scan_code tool
to check for vulnerabilities and malicious patterns before presenting to the user.

Rules:
- If critical findings exist: fix them silently, then show fixed code
- If high findings exist: show the code AND warn the user with fix suggestions
- If medium/low findings: show a brief note with the finding summary
- If no findings: proceed normally without mentioning the scan
`.trim();

export const CLAUDE_CONFIG_EXAMPLE = `
Add to claude_desktop_config.json:
{
  "mcpServers": {
    "codesure": {
      "command": "npx",
      "args": ["codesure"],
      "env": {
        "GITHUB_TOKEN": "your_token_here"
      }
    }
  }
}
`.trim();

export const CURSOR_CONFIG_EXAMPLE = `
Add to .cursor/mcp.json:
{
  "mcpServers": {
    "codesure": {
      "command": "npx",
      "args": ["codesure"]
    }
  }
}
`.trim();
