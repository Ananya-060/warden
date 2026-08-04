import fs from 'node:fs';
import { db } from '../db/index.js';
import { InspectorService } from './inspector.js';
import { PolicyEngineService } from './policy-engine.js';
import { AuditLogService } from './audit-log.js';
import { fetchPublicJson } from './remote-fetch.js';
import { MCPManifestSchema, VerifyResponse, WardenCertificate } from '@warden/shared';

function parseCertRow(r: any): WardenCertificate | null {
  try {
    const bodyStr: string | undefined =
      r.certificate_body ??
      (typeof r.expires_at === 'string' && r.expires_at.startsWith('{') ? r.expires_at : undefined);
    if (!bodyStr) return null;
    const cert: WardenCertificate = JSON.parse(bodyStr);
    if (r.status && !r.status.startsWith('20')) {
      cert.status = r.status;
    }
    return cert;
  } catch {
    return null;
  }
}

async function fetchManifestFromUrl(toolUrl: string): Promise<{ manifest: Record<string, unknown>; toolName: string }> {
  if (fs.existsSync(toolUrl)) {
    const content = fs.readFileSync(toolUrl, 'utf-8');
    const manifest = JSON.parse(content);
    return { manifest, toolName: (manifest.name as string) || 'unnamed-tool' };
  }

  const manifest = await fetchPublicJson(toolUrl);
  return { manifest, toolName: (manifest.name as string) || 'remote-mcp-tool' };
}

export async function verifyToolByUrl(toolUrl: string, actor = 'api:verify'): Promise<VerifyResponse> {
  const fetched = await fetchManifestFromUrl(toolUrl);
  const manifest = MCPManifestSchema.parse(fetched.manifest);
  const { toolName } = fetched;

  const scanResult = await InspectorService.inspectTool({
    tool_name: toolName,
    source_url: toolUrl,
    manifest,
    actor,
  });

  const scan = scanResult.scan;
  const findings = scanResult.findings;
  const toolHash = scan.tool_hash;
  const riskScore = findings.length;

  const allCertRows = db.prepare('SELECT * FROM certificates WHERE 1').all() as any[];
  const matchingCert = allCertRows
    .map(parseCertRow)
    .find((cert) => cert && cert.tool.hash === toolHash && cert.status === 'active');

  if (matchingCert) {
    AuditLogService.logEvent({
      event_type: 'tool_verify_allow',
      entity_id: matchingCert.certificate_id,
      actor,
      detail: { tool_url: toolUrl, tool_hash: toolHash, cached: false },
    });

    return {
      decision: 'allow',
      reason: `Certified ${matchingCert.issued_at.slice(0, 10)}, matches current policy.`,
      certificate_id: matchingCert.certificate_id,
      risk_score: riskScore,
      approved_capabilities: matchingCert.approved_capabilities,
    };
  }

  try {
    const decision = PolicyEngineService.evaluateScan(scan.id, undefined, actor);
    const outcome = decision.outcome as VerifyResponse['decision'];

    AuditLogService.logEvent({
      event_type: outcome === 'allow' ? 'tool_verify_allow' : 'tool_verify_block',
      entity_id: scan.id,
      actor,
      detail: { tool_url: toolUrl, tool_hash: toolHash, outcome, reason: decision.reason },
    });

    return {
      decision: outcome,
      reason: decision.reason,
      certificate_id: null,
      risk_score: riskScore,
      approved_capabilities: outcome === 'allow' ? (manifest.tools as any[])?.map((t) => t.name) || [] : undefined,
    };
  } catch {
    AuditLogService.logEvent({
      event_type: 'tool_verify_block',
      entity_id: scan.id,
      actor,
      detail: { tool_url: toolUrl, tool_hash: toolHash, reason: 'policy_evaluation_failed' },
    });

    return {
      decision: 'block',
      reason: 'No certificate found for this tool.',
      certificate_id: null,
      risk_score: riskScore,
    };
  }
}
