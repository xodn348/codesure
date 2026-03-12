// Privacy: this tool only sends the package NAME to registry.npmjs.org, never any user code.
import type { PackageCheckResult } from '../types.js';

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
  } catch {
    return null;
  }
}

async function fetchWeeklyDownloads(name: string): Promise<number | null> {
  try {
    const response = await fetch(`${NPM_DOWNLOADS_API}/${encodeURIComponent(name)}`);
    if (!response.ok) return null;
    const json = await response.json() as NpmDownloadsData;
    return json.downloads ?? null;
  } catch {
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
