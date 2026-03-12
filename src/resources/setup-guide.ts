import { CLAUDE_CONFIG_EXAMPLE, CURSOR_CONFIG_EXAMPLE, SYSTEM_PROMPT } from '../prompts/auto-scan.js';

export const SETUP_GUIDE = `
# CodeSure Setup Guide

## System Prompt (add to your AI agent configuration)
${SYSTEM_PROMPT}

## Claude Code Configuration
${CLAUDE_CONFIG_EXAMPLE}

## Cursor Configuration
${CURSOR_CONFIG_EXAMPLE}
`.trim();
