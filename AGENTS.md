<!-- ai-native:managed -->
# AGENTS.md

## Project Context
- **Type**: MCP stdio server (security scanner)
- **Package Manager**: npm
- **Node Version**: >=18
- **Runtime**: bun (test), node (production via npx)
- **MCP SDK**: @modelcontextprotocol/sdk ^1.0.0
- **AST**: web-tree-sitter (WASM, no native bindings)
- **YAML**: js-yaml for Semgrep-compatible rule loading

## Development Workflow

```bash
# Install dependencies
npm install

# Build
npm run build      # tsc + chmod +x dist/index.js

# Run tests
bun test           # All 152 tests
bun test src/engine/regex-engine.test.ts  # Single file

# Type checking
npm run typecheck   # tsc --noEmit

# Run MCP server (stdio)
node dist/index.js  # Speaks JSON-RPC over stdin/stdout

# Auto-install to AI clients
npx codesure install
```

## TypeScript
- **Strict mode**: Enabled
- **Target**: ES2022, Module: Node16, ESM (`"type": "module"`)
- **NO `any` type** (use `unknown` and narrow)
- **Explicit return types** for exported functions
- All imports use `.js` extension (ESM requirement)
- Use `server.registerTool()` NOT `server.tool()` (deprecated)

## Constraints (DO NOT)
- DO NOT add external API calls to scan_code path (privacy guarantee)
- DO NOT add telemetry, analytics, or tracking code
- DO NOT use native tree-sitter bindings (cross-platform npm compatibility)
- DO NOT use `as any` or `@ts-ignore`
- DO NOT delete failing tests to make them pass
- DO NOT send user code to any external service