import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CertificateCache } from '../src/cache.js';
import type { WardenCertificate } from '@warden/shared';

const sampleCert: WardenCertificate = {
  warden_certificate_version: '1.0',
  certificate_id: 'cert-test-123',
  tool: { name: 'test-tool', hash: 'sha256:abc123', version: '1.0.0' },
  approved_capabilities: ['read'],
  risk_summary: { findings_count: 0, highest_severity: 'none', notes: '' },
  decision: { outcome: 'allow', reason: 'Test policy' },
  issuer: { org_id: 'org-1', org_name: 'Test Org', public_key: 'ed25519:00' },
  issued_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 86400000).toISOString(),
  signature: 'dGVzdA==',
  status: 'active',
};

describe('CertificateCache', () => {
  let cacheDir: string;
  let cache: CertificateCache;

  beforeEach(() => {
    cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-cache-'));
    cache = new CertificateCache(cacheDir, 60000);
  });

  afterEach(() => {
    fs.rmSync(cacheDir, { recursive: true, force: true });
  });

  it('stores and retrieves cached certificates', () => {
    cache.set('samples/test/manifest.json', sampleCert);
    const entry = cache.get('samples/test/manifest.json');
    expect(entry).not.toBeNull();
    expect(entry?.certificate.certificate_id).toBe('cert-test-123');
  });

  it('invalidates by certificate id', () => {
    cache.set('tool-a', sampleCert);
    cache.invalidateByCertificateId('cert-test-123');
    expect(cache.get('tool-a')).toBeNull();
  });

  it('returns null for revoked certificates', () => {
    cache.set('tool-b', { ...sampleCert, status: 'revoked' });
    expect(cache.get('tool-b')).toBeNull();
  });
});
