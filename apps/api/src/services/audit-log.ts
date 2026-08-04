import { db } from '../db/index.js';
import { computeAuditRowHash, canonicalizeJson } from '@warden/shared';

export interface AuditEventInput {
  event_type: string;
  entity_id?: string | null;
  actor: string;
  detail: Record<string, unknown>;
}

export class AuditLogService {
  /**
   * Appends an immutable, hash-chained audit log entry.
   */
  static logEvent(input: AuditEventInput): number {
    const lastRow = db
      .prepare('SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1')
      .get() as { row_hash: string } | undefined;

    const prevRowHash = lastRow?.row_hash || '0000000000000000000000000000000000000000000000000000000000000000';
    const createdAt = new Date().toISOString();

    const payload = {
      event_type: input.event_type,
      entity_id: input.entity_id || null,
      actor: input.actor,
      detail: input.detail,
      created_at: createdAt,
    };

    const rowHash = computeAuditRowHash(prevRowHash, payload);

    const result = db
      .prepare(
        `INSERT INTO audit_log (event_type, entity_id, actor, detail, prev_row_hash, row_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        input.event_type,
        input.entity_id || null,
        input.actor,
        JSON.stringify(input.detail),
        prevRowHash,
        rowHash,
        createdAt
      );

    return Number(result.lastInsertRowid);
  }

  /**
   * Verifies the cryptographic tamper-evident integrity of the entire audit chain.
   */
  static verifyChainIntegrity(): { valid: boolean; total_rows: number; invalid_at_id?: number; reason?: string } {
    const rows = db.prepare('SELECT * FROM audit_log ORDER BY id ASC').all() as any[];
    
    let expectedPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';

    for (const row of rows) {
      if (row.prev_row_hash !== expectedPrevHash) {
        return {
          valid: false,
          total_rows: rows.length,
          invalid_at_id: row.id,
          reason: `Previous hash mismatch on row ${row.id}. Expected ${expectedPrevHash}, got ${row.prev_row_hash}`,
        };
      }

      let detailObj = {};
      try {
        detailObj = JSON.parse(row.detail || '{}');
      } catch (e) {}

      const payload = {
        event_type: row.event_type,
        entity_id: row.entity_id || null,
        actor: row.actor,
        detail: detailObj,
        created_at: row.created_at,
      };

      const calculatedHash = computeAuditRowHash(row.prev_row_hash, payload);
      if (calculatedHash !== row.row_hash) {
        return {
          valid: false,
          total_rows: rows.length,
          invalid_at_id: row.id,
          reason: `Row hash integrity failure at ID ${row.id}. Stored ${row.row_hash}, calculated ${calculatedHash}`,
        };
      }

      expectedPrevHash = row.row_hash;
    }

    return { valid: true, total_rows: rows.length };
  }

  /**
   * Returns recent audit logs with pagination / filter.
   */
  static getLogs(limit = 100): any[] {
    const rows = db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(limit) as any[];
    return rows.map((r) => ({
      ...r,
      detail: JSON.parse(r.detail || '{}'),
    }));
  }
}
