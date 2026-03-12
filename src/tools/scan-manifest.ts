import type { ManifestCheckResult, Finding, Severity } from '../types.js';
import { DANGEROUS_PERMISSIONS } from '../constants.js';

type ManifestType = 'chrome_extension' | 'vscode_extension' | 'package_json';

// Top-10 npm packages for typosquatting detection
const TOP_NPM_PACKAGES = [
  'lodash', 'express', 'request', 'react', 'axios',
  'moment', 'chalk', 'commander', 'debug', 'async',
];

function editDistance(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

function makeFinding(
  id: string,
  severity: Severity,
  message: string,
  ruleId: string,
  snippet?: string,
  fixSuggestion?: string,
): Finding {
  return {
    id,
    severity,
    category: 'malicious',
    confidence: 90,
    rule_id: ruleId,
    message,
    location: {},
    snippet,
    fix_suggestion: fixSuggestion,
  };
}

function detectType(parsed: Record<string, unknown>): ManifestType {
  if ('manifest_version' in parsed) return 'chrome_extension';
  if ('contributes' in parsed) return 'vscode_extension';
  return 'package_json';
}

function analyzeChromeExtension(parsed: Record<string, unknown>): ManifestCheckResult {
  const findings: Finding[] = [];
  const permissions: string[] = Array.isArray(parsed['permissions'])
    ? (parsed['permissions'] as unknown[]).filter((p): p is string => typeof p === 'string')
    : [];

  const dangerousFound = permissions.filter(p => DANGEROUS_PERMISSIONS.includes(p));

  // Dangerous combos — severity escalation
  const hasAllUrls = permissions.includes('<all_urls>');
  const hasCookies = permissions.includes('cookies');
  const hasWebRequest = permissions.includes('webRequest');

  if (hasAllUrls && hasCookies && hasWebRequest) {
    findings.push(makeFinding(
      'MANIFEST-001',
      'critical',
      'Dangerous permission combo: <all_urls> + cookies + webRequest allows full traffic interception and cookie theft',
      'MANIFEST-PERM-COMBO-CRITICAL',
      `permissions: ${JSON.stringify(permissions)}`,
      'Remove <all_urls> and restrict to specific origins; avoid combining cookies + webRequest',
    ));
  } else if (hasAllUrls && hasCookies) {
    findings.push(makeFinding(
      'MANIFEST-002',
      'high',
      'Dangerous permission combo: <all_urls> + cookies allows reading cookies from all sites',
      'MANIFEST-PERM-COMBO-HIGH',
      `permissions: ${JSON.stringify(permissions)}`,
      'Restrict host permissions to specific origins instead of <all_urls>',
    ));
  } else if (hasAllUrls) {
    findings.push(makeFinding(
      'MANIFEST-003',
      'medium',
      '<all_urls> grants access to all websites — prefer specific host patterns',
      'MANIFEST-PERM-ALL-URLS',
      `permissions: ${JSON.stringify(permissions)}`,
      'Replace <all_urls> with specific host patterns like https://example.com/*',
    ));
  }

  // CSP checks
  const csp = parsed['content_security_policy'];
  const cspString = typeof csp === 'string' ? csp
    : typeof csp === 'object' && csp !== null && 'extension_pages' in csp
      ? String((csp as Record<string, unknown>)['extension_pages'])
      : '';

  if (cspString.includes('unsafe-eval')) {
    findings.push(makeFinding(
      'MANIFEST-004',
      'high',
      "CSP contains 'unsafe-eval' which allows dynamic code execution via eval()",
      'MANIFEST-CSP-UNSAFE-EVAL',
      `content_security_policy: ${cspString}`,
      "Remove 'unsafe-eval' from CSP",
    ));
  }
  if (cspString.includes('unsafe-inline')) {
    findings.push(makeFinding(
      'MANIFEST-005',
      'medium',
      "CSP contains 'unsafe-inline' which allows inline scripts and styles",
      'MANIFEST-CSP-UNSAFE-INLINE',
      `content_security_policy: ${cspString}`,
      "Remove 'unsafe-inline' from CSP",
    ));
  }

  // Content scripts remote URL check
  const contentScripts = parsed['content_scripts'];
  if (Array.isArray(contentScripts)) {
    for (const cs of contentScripts) {
      if (typeof cs !== 'object' || cs === null) continue;
      const csObj = cs as Record<string, unknown>;
      const jsFiles = Array.isArray(csObj['js']) ? csObj['js'] : [];
      const cssFiles = Array.isArray(csObj['css']) ? csObj['css'] : [];
      const allFiles = [...jsFiles, ...cssFiles];
      for (const file of allFiles) {
        if (typeof file === 'string' && (file.startsWith('http://') || file.startsWith('https://'))) {
          findings.push(makeFinding(
            'MANIFEST-006',
            'critical',
            `Content script loads from remote URL: ${file} — allows remote code execution`,
            'MANIFEST-CONTENT-SCRIPT-REMOTE',
            `content_scripts js/css: ${file}`,
            'Only use local bundled scripts in content_scripts',
          ));
        }
      }
    }
  }

  const permissionsScore = Math.min(dangerousFound.length * 10, 100);

  return {
    permissions_score: permissionsScore,
    dangerous_permissions: dangerousFound,
    findings,
  };
}

const SHELL_PATTERNS = ['curl', 'wget', 'bash', 'sh ', 'node -e', 'python -c'];

function analyzePackageJson(parsed: Record<string, unknown>): ManifestCheckResult {
  const findings: Finding[] = [];

  // Check lifecycle scripts for shell commands
  const scripts = parsed['scripts'];
  if (typeof scripts === 'object' && scripts !== null) {
    const scriptsObj = scripts as Record<string, unknown>;
    for (const hook of ['postinstall', 'preinstall']) {
      const scriptValue = scriptsObj[hook];
      if (typeof scriptValue === 'string') {
        const lower = scriptValue.toLowerCase();
        const matched = SHELL_PATTERNS.find(p => lower.includes(p));
        if (matched) {
          findings.push(makeFinding(
            'PKG-001',
            'critical',
            `${hook} script executes shell commands (matched: '${matched}') — potential supply-chain attack`,
            'PKG-LIFECYCLE-SHELL',
            `${hook}: "${scriptValue}"`,
            `Avoid shell commands in ${hook}; use a Node.js script instead`,
          ));
        }
      }
    }
  }

  // Typosquatting check on dependencies
  const deps = parsed['dependencies'];
  const devDeps = parsed['devDependencies'];
  const allDeps: string[] = [
    ...(typeof deps === 'object' && deps !== null ? Object.keys(deps) : []),
    ...(typeof devDeps === 'object' && devDeps !== null ? Object.keys(devDeps) : []),
  ];

  for (const dep of allDeps) {
    for (const safe of TOP_NPM_PACKAGES) {
      if (dep !== safe && editDistance(dep, safe) === 1) {
        findings.push(makeFinding(
          'PKG-002',
          'medium',
          `Package '${dep}' is 1 character away from '${safe}' — possible typosquatting`,
          'PKG-TYPOSQUATTING',
          `dependency: "${dep}"`,
          `Verify you intended '${dep}' and not '${safe}'`,
        ));
        break;
      }
    }
  }

  return {
    permissions_score: 0,
    dangerous_permissions: [],
    findings,
  };
}

export function scanManifest(
  manifestContent: string,
  type?: ManifestType,
): ManifestCheckResult {
  let parsed: Record<string, unknown>;

  try {
    const raw: unknown = JSON.parse(manifestContent);
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      return {
        permissions_score: 0,
        dangerous_permissions: [],
        findings: [makeFinding(
          'MANIFEST-PARSE-ERR',
          'high',
          'Manifest JSON is not an object',
          'MANIFEST-INVALID-JSON',
        )],
      };
    }
    parsed = raw as Record<string, unknown>;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      permissions_score: 0,
      dangerous_permissions: [],
      findings: [makeFinding(
        'MANIFEST-PARSE-ERR',
        'high',
        `Failed to parse manifest JSON: ${message}`,
        'MANIFEST-INVALID-JSON',
      )],
    };
  }

  const resolvedType = type ?? detectType(parsed);

  if (resolvedType === 'chrome_extension') return analyzeChromeExtension(parsed);
  if (resolvedType === 'package_json') return analyzePackageJson(parsed);

  // vscode_extension — basic pass-through for now
  return {
    permissions_score: 0,
    dangerous_permissions: [],
    findings: [],
  };
}
