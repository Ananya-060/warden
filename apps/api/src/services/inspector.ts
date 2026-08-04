import { db } from '../db/index.js';
import { RiskEngine } from './risk-engine.js';
import { AuditLogService } from './audit-log.js';
import {
  canonicalizeJson,
  computeSha256,
  MCPManifest,
  MCPManifestSchema,
  RiskFinding,
  Scan,
} from '@warden/shared';
import crypto from 'node:crypto';

export interface ScanToolInput {
  org_id?: string;
  tool_name: string;
  source_url?: string;
  manifest: MCPManifest;
  actor?: string;
}

export class InspectorService {
  /**
   * Performs inspection of an MCP tool manifest, computes canonical hash, runs risk engine,
   * diffs against past version, saves scan record, and logs audit event.
   */
  static async inspectTool(input: ScanToolInput): Promise<{ scan: Scan; findings: RiskFinding[]; diff: string | null }> {
    const orgId = input.org_id || '0e210000-0000-4000-8000-000000000001';
    const actor = input.actor || 'system:cli';

    // Validate manifest structure
    const parsedManifest = MCPManifestSchema.parse(input.manifest);

    // Compute canonical SHA-256 hash of manifest
    const canonicalManifestStr = canonicalizeJson(parsedManifest);
    const toolHash = computeSha256(canonicalManifestStr);

    // Get or create Tool in DB
    let toolRow = db
      .prepare('SELECT * FROM tools WHERE org_id = ? AND name = ? LIMIT 1')
      .get(orgId, input.tool_name) as any;

    const now = new Date().toISOString();
    if (!toolRow) {
      const toolId = crypto.randomUUID();
      db.prepare(
        'INSERT INTO tools (id, org_id, name, source_url, created_at) VALUES (?, ?, ?, ?, ?)'
      ).run(toolId, orgId, input.tool_name, input.source_url || null, now);
      toolRow = { id: toolId, org_id: orgId, name: input.tool_name, source_url: input.source_url };
    }

    // Check previous scan to calculate structural diff
    const lastScanRow = db
      .prepare('SELECT manifest FROM scans WHERE tool_id = ? ORDER BY scanned_at DESC LIMIT 1')
      .get(toolRow.id) as { manifest: string } | undefined;

    let diffText: string | null = null;
    if (lastScanRow) {
      try {
        const prevManifest: MCPManifest = JSON.parse(lastScanRow.manifest);
        diffText = this.computeManifestDiff(prevManifest, parsedManifest);
      } catch (e) {}
    }

    // Run static risk checkers
    const findings = RiskEngine.analyzeManifest(parsedManifest);

    // Persist scan record
    const scanId = crypto.randomUUID();
    db.prepare(
      `INSERT INTO scans (id, tool_id, tool_hash, manifest, findings, scanned_at, scanned_by)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(
      scanId,
      toolRow.id,
      toolHash,
      JSON.stringify(parsedManifest),
      JSON.stringify(findings),
      now,
      actor
    );

    const scanRecord: Scan = {
      id: scanId,
      tool_id: toolRow.id,
      tool_hash: toolHash,
      manifest: parsedManifest,
      findings,
      scanned_at: now,
      scanned_by: actor,
    };

    // Record Audit Log event
    AuditLogService.logEvent({
      event_type: 'scan_created',
      entity_id: scanId,
      actor,
      detail: {
        tool_name: input.tool_name,
        tool_hash: toolHash,
        findings_count: findings.length,
        highest_severity: this.getHighestSeverity(findings),
        diff: diffText,
      },
    });

    return {
      scan: scanRecord,
      findings,
      diff: diffText,
    };
  }

  private static computeManifestDiff(oldM: MCPManifest, newM: MCPManifest): string {
    const changes: string[] = [];

    const oldTools = new Set((oldM.tools || []).map((t) => t.name));
    const newTools = new Set((newM.tools || []).map((t) => t.name));

    for (const t of newTools) {
      if (!oldTools.has(t)) changes.push(`+ Tool added: '${t}'`);
    }
    for (const t of oldTools) {
      if (!newTools.has(t)) changes.push(`- Tool removed: '${t}'`);
    }

    const oldPerms = new Set(oldM.permissions || []);
    const newPerms = new Set(newM.permissions || []);

    for (const p of newPerms) {
      if (!oldPerms.has(p)) changes.push(`+ Permission added: '${p}'`);
    }
    for (const p of oldPerms) {
      if (!newPerms.has(p)) changes.push(`- Permission removed: '${p}'`);
    }

    return changes.length > 0 ? changes.join('\n') : 'No structural changes detected.';
  }

  public static getHighestSeverity(findings: RiskFinding[]): string {
    if (findings.some((f) => f.severity === 'critical')) return 'critical';
    if (findings.some((f) => f.severity === 'high')) return 'high';
    if (findings.some((f) => f.severity === 'medium')) return 'medium';
    if (findings.some((f) => f.severity === 'low')) return 'low';
    return 'none';
  }
}
