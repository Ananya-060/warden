import { db } from '../db/index.js';
import { AuditLogService } from './audit-log.js';
import { InspectorService } from './inspector.js';
import {
  canonicalizeJson,
  signCanonicalJson,
  verifyCanonicalJsonSignature,
  WardenCertificate,
  WardenCertificateBody,
  RiskFinding,
} from '@warden/shared';
import crypto from 'node:crypto';

export class CertificateAuthorityService {
  /**
   * Issues a cryptographically signed Warden Trust Certificate for an approved scan/decision.
   */
  static async issueCertificate(decisionId: string, actor = 'system:cli'): Promise<WardenCertificate> {
    const decisionRow = db.prepare('SELECT * FROM decisions WHERE id = ?').get(decisionId) as any;
    if (!decisionRow) {
      throw new Error(`Decision '${decisionId}' not found.`);
    }

    if (decisionRow.outcome === 'block') {
      throw new Error('Cannot issue trust certificate for a BLOCKED decision.');
    }

    const scanRow = db.prepare('SELECT * FROM scans WHERE id = ?').get(decisionRow.scan_id) as any;
    const toolRow = db.prepare('SELECT * FROM tools WHERE id = ?').get(scanRow.tool_id) as any;
    const orgRow = db.prepare('SELECT * FROM organizations WHERE id = ?').get(toolRow.org_id) as any;

    if (!orgRow) {
      throw new Error(`Organization '${toolRow.org_id}' not found.`);
    }

    const manifest = JSON.parse(scanRow.manifest);
    const findings: RiskFinding[] = JSON.parse(scanRow.findings || '[]');
    const approvedCapabilities = (manifest.tools || []).map((t: any) => t.name);

    const certificateId = crypto.randomUUID();
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + 365 * 24 * 60 * 60 * 1000); // 12 months validity

    const certBody: WardenCertificateBody = {
      warden_certificate_version: '1.0',
      certificate_id: certificateId,
      tool: {
        name: toolRow.name,
        source_url: toolRow.source_url || manifest.source_url || '',
        hash: scanRow.tool_hash,
        version: manifest.version || '1.0.0',
      },
      approved_capabilities: approvedCapabilities,
      risk_summary: {
        findings_count: findings.length,
        highest_severity: InspectorService.getHighestSeverity(findings),
        notes: findings.map((f) => f.description).join('; ') || 'No risk findings detected.',
      },
      decision: {
        outcome: decisionRow.outcome,
        reason: decisionRow.reason,
      },
      issuer: {
        org_id: orgRow.id,
        org_name: orgRow.name,
        public_key: orgRow.ca_public_key,
      },
      issued_at: issuedAt.toISOString(),
      expires_at: expiresAt.toISOString(),
    };

    // Sign canonical certificate body using CA Ed25519 private key
    const signature = await signCanonicalJson(certBody, orgRow.ca_private_key);

    const certificateRecord: WardenCertificate = {
      ...certBody,
      signature,
      status: 'active',
    };

    db.prepare(
      `INSERT INTO certificates (id, decision_id, tool_id, tool_hash, approved_capabilities, risk_summary, issuer_org_id, signature, status, issued_at, expires_at, certificate_body)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      certificateId,
      decisionRow.id,
      toolRow.id,
      scanRow.tool_hash,
      JSON.stringify(approvedCapabilities),
      JSON.stringify(certBody.risk_summary),
      orgRow.id,
      signature,
      'active',
      issuedAt.toISOString(),
      expiresAt.toISOString(),
      JSON.stringify(certificateRecord)
    );

    AuditLogService.logEvent({
      event_type: 'cert_issued',
      entity_id: certificateId,
      actor,
      detail: {
        tool_name: toolRow.name,
        tool_hash: scanRow.tool_hash,
        outcome: decisionRow.outcome,
        issuer_org: orgRow.name,
        expires_at: expiresAt.toISOString(),
      },
    });

    return certificateRecord;
  }

  /**
   * Verifies an existing certificate offline or against live tool hash.
   */
  static async verifyCertificate(
    cert: WardenCertificate,
    currentToolHash?: string
  ): Promise<{ valid: boolean; signature_valid: boolean; hash_matched: boolean; status: string; reason: string }> {
    // 1. Extract body without signature for verification
    const { signature, status, ...certBody } = cert;

    // 2. Verify signature
    const signatureValid = await verifyCanonicalJsonSignature(
      certBody,
      signature,
      cert.issuer.public_key
    );

    if (!signatureValid) {
      return {
        valid: false,
        signature_valid: false,
        hash_matched: false,
        status: 'invalidated',
        reason: 'Cryptographic signature verification failed. Certificate may be forged or altered.',
      };
    }

    // 3. Expiry check
    if (new Date(cert.expires_at) < new Date()) {
      return {
        valid: false,
        signature_valid: true,
        hash_matched: true,
        status: 'expired',
        reason: `Certificate expired on ${cert.expires_at}.`,
      };
    }

    // 4. Live Tool Hash match check
    let hashMatched = true;
    if (currentToolHash && currentToolHash !== cert.tool.hash) {
      hashMatched = false;

      // Update certificate status in database if stored
      db.prepare("UPDATE certificates SET status = 'invalidated' WHERE id = ?").run(cert.certificate_id);

      AuditLogService.logEvent({
        event_type: 'cert_invalidated',
        entity_id: cert.certificate_id,
        actor: 'system:verifier',
        detail: {
          reason: 'Tool hash mismatch detected during verification',
          expected_hash: cert.tool.hash,
          current_hash: currentToolHash,
        },
      });

      return {
        valid: false,
        signature_valid: true,
        hash_matched: false,
        status: 'invalidated',
        reason: `Tool hash mismatch! Certified hash '${cert.tool.hash}', but current live hash is '${currentToolHash}'. Tool code or manifest was modified.`,
      };
    }

    return {
      valid: cert.status === 'active',
      signature_valid: true,
      hash_matched: true,
      status: cert.status,
      reason: cert.status === 'active' ? 'Certificate is active, cryptographically valid, and matches current tool hash.' : `Certificate status is '${cert.status}'.`,
    };
  }
}
