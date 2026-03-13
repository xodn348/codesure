import type { Finding, AgentInfo } from '../types.js';
import { CodeSureError } from '../errors.js';

interface AnonymizedPattern {
  type: string;
  taxonomy?: string;
  language: string;
  confidence: number;
  pattern: string;
  indicators: string[];
  agent: AgentInfo;
  timestamp: string;
}

interface ReportResult {
  success: boolean;
  message: string;
  url?: string;
}

interface GitHubIssueResponse {
  html_url: string;
  number: number;
}

/**
 * Derives abstract language name from file extension.
 * Returns 'unknown' if no file path or unrecognized extension.
 */
function extractLanguage(filePath?: string): string {
  if (!filePath) return 'unknown';
  const ext = filePath.split('.').pop()?.toLowerCase();
  const extMap: Record<string, string> = {
    ts: 'typescript',
    tsx: 'typescript',
    js: 'javascript',
    jsx: 'javascript',
    py: 'python',
    rb: 'ruby',
    go: 'go',
    rs: 'rust',
    java: 'java',
    cs: 'csharp',
    php: 'php',
    sh: 'bash',
    bash: 'bash',
  };
  return ext ? (extMap[ext] ?? 'unknown') : 'unknown';
}

/**
 * Converts a rule_id slug into an abstract pattern description.
 * e.g. "eval-injection" → "dynamic_eval_execution"
 */
function abstractifyRuleId(ruleId: string): string {
  return ruleId.replace(/-/g, '_');
}

/**
 * Transforms a Finding into an anonymized pattern report.
 * Strips all user code, file paths, and variable names.
 */
export function anonymizePattern(finding: Finding, agentInfo: AgentInfo): AnonymizedPattern {
  const language = extractLanguage(finding.location.file);
  const pattern = abstractifyRuleId(finding.rule_id);
  const indicators = finding.evidence_chain?.map(abstractifyRuleId) ?? [finding.rule_id];

  return {
    type: finding.category,
    taxonomy: finding.taxonomy,
    language,
    confidence: finding.confidence,
    pattern,
    indicators,
    agent: { name: agentInfo.name, version: agentInfo.version },
    timestamp: new Date().toISOString(),
  };
}

/**
 * Reports an anonymized pattern to the CodeSure community rules repo via GitHub Issues.
 * Requires GITHUB_TOKEN env var. Returns graceful error if missing.
 */
export async function reportPattern(
  finding: Finding,
  agentInfo: AgentInfo
): Promise<ReportResult> {
  const token = process.env['GITHUB_TOKEN'];
  if (!token) {
    return {
      success: false,
      message: 'GitHub token not configured. Set GITHUB_TOKEN to enable pattern reporting.',
    };
  }

  const anonymized = anonymizePattern(finding, agentInfo);
  const agentLabel = anonymized.agent.name.toLowerCase().replace(/\s+/g, '-');
  const taxonomyLabel = anonymized.taxonomy ?? 'unknown';

  const issueBody = {
    title: `New Pattern: ${anonymized.type} - ${taxonomyLabel} [${anonymized.language}]`,
    body: JSON.stringify(anonymized, null, 2),
    labels: [
      'new-pattern',
      `language:${anonymized.language}`,
      `taxonomy:${taxonomyLabel}`,
      `agent:${agentLabel}`,
    ],
  };

  try {
    const response = await fetch(
      'https://api.github.com/repos/xodn348/codesure-rules/issues',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          'User-Agent': 'codesure-mcp/1.0.0',
        },
        body: JSON.stringify(issueBody),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      return {
        success: false,
        message: `GitHub API error ${response.status}: ${errorText}`,
      };
    }

    const issue = (await response.json()) as GitHubIssueResponse;
    return {
      success: true,
      message: 'Pattern reported successfully',
      url: issue.html_url,
    };
  } catch (cause) {
    const err = new CodeSureError('GITHUB_API_FAILED', 'Failed to report pattern to GitHub', { retryable: true, context: { repo: 'xodn348/codesure-rules' }, cause });
    return { success: false, message: err.message };
  }
}
