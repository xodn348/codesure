// Privacy: this tool only sends the package NAME to registry.npmjs.org, never any user code.
import type { PackageCheckResult } from '../types.js';
import { CodeSureError } from '../errors.js';

const NPM_REGISTRY = 'https://registry.npmjs.org';
const NPM_DOWNLOADS_API = 'https://api.npmjs.org/downloads/point/last-week';

interface NpmPackageData {
  name: string;
  'dist-tags': { latest: string };
  time: Record<string, string>;
  maintainers: Array<{ name: string; email: string }>;
  versions: Record<string, { scripts?: Record<string, string> }>;
}

interface NpmDownloadsData {
  downloads: number;
  package: string;
}

/**
 * Checks an npm package for supply-chain risks and typosquatting.
 *
 * Queries the npm registry for package metadata and evaluates risk signals:
 * staleness (>2 years), lifecycle scripts (postinstall/preinstall), and
 * new single-maintainer packages (<30 days old).
 *
 * @param name - npm package name to check. Only the name is sent to the registry.
 * @returns Risk assessment with score (0-100), existence flag, and issue descriptions.
 */
export async function checkPackage(name: string): Promise<PackageCheckResult> {
  const data = await fetchPackageMetadata(name);

  if (data === null) {
    return {
      name,
      exists: false,
      risk_score: 100,
      issues: ['Package does not exist on npm registry — possible AI hallucination or typosquatting'],
    };
  }

  const { score, issues } = assessRisk(data);
  return { name, exists: true, risk_score: score, issues };
}

export async function fetchPackageMetadata(name: string): Promise<NpmPackageData | null> {
  try {
    const response = await fetch(`${NPM_REGISTRY}/${encodeURIComponent(name)}`);
    if (response.status === 404) {
      return null;
    }
    const json = await response.json() as NpmPackageData;
    return json;
  } catch (cause) {
    const err = new CodeSureError('NETWORK_FAILED', `Failed to fetch npm metadata for "${name}"`, { retryable: true, context: { packageName: name }, cause });
    console.warn(`[codesure] ${err.message}`);
    return null;
  }
}

async function fetchWeeklyDownloads(name: string): Promise<number | null> {
  try {
    const response = await fetch(`${NPM_DOWNLOADS_API}/${encodeURIComponent(name)}`);
    if (!response.ok) return null;
    const json = await response.json() as NpmDownloadsData;
    return json.downloads ?? null;
  } catch (cause) {
    const err = new CodeSureError('NETWORK_FAILED', `Failed to fetch download stats for "${name}"`, { retryable: true, context: { packageName: name }, cause });
    console.warn(`[codesure] ${err.message}`);
    return null;
  }
}

export function assessRisk(data: NpmPackageData): { score: number; issues: string[] } {
  const issues: string[] = [];
  let score = 0;

  const modifiedStr = data.time?.modified;
  if (modifiedStr) {
    const lastModified = new Date(modifiedStr);
    const twoYearsAgo = new Date();
    twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);
    if (lastModified < twoYearsAgo) {
      score += 15;
      issues.push('Package not updated in over 2 years');
    }
  }

  const latestVersion = data['dist-tags']?.latest;
  if (latestVersion) {
    const versionData = data.versions?.[latestVersion];
    const scripts = versionData?.scripts ?? {};

    if (scripts['postinstall'] !== undefined) {
      score += 25;
      issues.push('Has postinstall script — review carefully');
    }

    if (scripts['preinstall'] !== undefined) {
      score += 25;
      issues.push('Has preinstall script');
    }
  }

  const createdStr = data.time?.created;
  const maintainerCount = data.maintainers?.length ?? 0;
  if (createdStr && maintainerCount === 1) {
    const created = new Date(createdStr);
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    if (created > thirtyDaysAgo) {
      score += 20;
      issues.push('New package with single maintainer');
    }
  }

  return { score: Math.min(score, 100), issues };
}

export async function assessRiskWithDownloads(
  data: NpmPackageData
): Promise<{ score: number; issues: string[] }> {
  const { score: baseScore, issues } = assessRisk(data);
  let score = baseScore;

  const downloads = await fetchWeeklyDownloads(data.name);
  if (downloads !== null && downloads < 100) {
    score += 20;
    issues.unshift('Low download count (possible typosquatting)');
  }

  return { score: Math.min(score, 100), issues };
}
