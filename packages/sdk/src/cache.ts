import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { computeSha256, verifyCanonicalJsonSignature } from '@warden/shared';
import type { CachedCertificateEntry, VerifyResponse, WardenCertificate } from './types.js';

export class CertificateCache {
  private cacheDir: string;
  private ttlMs: number;

  constructor(cacheDir?: string, ttlMs = 24 * 60 * 60 * 1000) {
    this.cacheDir = cacheDir || path.join(os.homedir(), '.warden', 'cache');
    this.ttlMs = ttlMs;
    fs.mkdirSync(this.cacheDir, { recursive: true });
  }

  private cachePath(toolUrl: string): string {
    const hash = computeSha256(toolUrl, true);
    return path.join(this.cacheDir, `${hash}.json`);
  }

  get(toolUrl: string): CachedCertificateEntry | null {
    const filePath = this.cachePath(toolUrl);
    if (!fs.existsSync(filePath)) {
      return null;
    }

    try {
      const entry = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as CachedCertificateEntry;
      const age = Date.now() - new Date(entry.cachedAt).getTime();
      if (age > this.ttlMs) {
        return null;
      }
      if (entry.certificate.status === 'revoked') {
        return null;
      }
      if (new Date(entry.certificate.expires_at) < new Date()) {
        return null;
      }
      return entry;
    } catch {
      return null;
    }
  }

  set(toolUrl: string, certificate: WardenCertificate): void {
    const entry: CachedCertificateEntry = {
      certificate,
      cachedAt: new Date().toISOString(),
      toolUrl,
    };
    fs.writeFileSync(this.cachePath(toolUrl), JSON.stringify(entry, null, 2), 'utf-8');
  }

  invalidate(toolUrl: string): void {
    const filePath = this.cachePath(toolUrl);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }

  invalidateByCertificateId(certificateId: string): void {
    if (!fs.existsSync(this.cacheDir)) {
      return;
    }

    for (const file of fs.readdirSync(this.cacheDir)) {
      const filePath = path.join(this.cacheDir, file);
      try {
        const entry = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as CachedCertificateEntry;
        if (entry.certificate.certificate_id === certificateId) {
          fs.unlinkSync(filePath);
        }
      } catch {
        // ignore malformed cache files
      }
    }
  }

  async verifyOffline(entry: CachedCertificateEntry, currentManifestHash?: string): Promise<VerifyResponse | null> {
    const { signature, status, ...body } = entry.certificate;
    const signatureValid = await verifyCanonicalJsonSignature(body, signature, entry.certificate.issuer.public_key);

    if (!signatureValid || entry.certificate.status !== 'active') {
      return null;
    }

    if (currentManifestHash && currentManifestHash !== entry.certificate.tool.hash) {
      return {
        decision: 'block',
        reason: 'Tool code or manifest has changed since certification.',
        certificate_id: entry.certificate.certificate_id,
        risk_score: entry.certificate.risk_summary.findings_count,
      };
    }

    return {
      decision: entry.certificate.decision.outcome,
      reason: `Cached certificate verified offline. ${entry.certificate.decision.reason}`,
      certificate_id: entry.certificate.certificate_id,
      risk_score: entry.certificate.risk_summary.findings_count,
      approved_capabilities: entry.certificate.approved_capabilities,
    };
  }
}
