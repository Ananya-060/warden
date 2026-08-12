import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { generateEd25519KeyPair } from '@warden/shared';

const DB_PATH = process.env.WARDEN_DB_PATH || path.join(process.cwd(), 'warden_db.json');

interface TablesData {
  organizations: any[];
  tools: any[];
  scans: any[];
  policies: any[];
  decisions: any[];
  certificates: any[];
  audit_log: any[];
  api_keys: any[];
  webhook_subscriptions: any[];
  webhook_deliveries: any[];
}

class WardenDatabase {
  private data: TablesData = {
    organizations: [],
    tools: [],
    scans: [],
    policies: [],
    decisions: [],
    certificates: [],
    audit_log: [],
    api_keys: [],
    webhook_subscriptions: [],
    webhook_deliveries: [],
  };

  constructor() {
    this.load();
  }

  private load() {
    if (fs.existsSync(DB_PATH)) {
      try {
        const content = fs.readFileSync(DB_PATH, 'utf-8');
        this.data = { ...this.data, ...JSON.parse(content) };
        if (!this.data.api_keys) this.data.api_keys = [];
        if (!this.data.webhook_subscriptions) this.data.webhook_subscriptions = [];
        if (!this.data.webhook_deliveries) this.data.webhook_deliveries = [];
      } catch (e) {
        this.save();
      }
    } else {
      this.save();
    }
  }

  public save() {
    fs.writeFileSync(DB_PATH, JSON.stringify(this.data, null, 2), 'utf-8');
  }

  public exec(sql: string) {
    // Schema initialization stub (tables pre-created in data)
  }

  public prepare(sql: string) {
    const dbInstance = this;

    return {
      run(...params: any[]) {
        const sqlUpper = sql.trim().toUpperCase();

        if (sqlUpper.startsWith('INSERT INTO ORGANIZATIONS')) {
          dbInstance.data.organizations.push({
            id: params[0],
            name: params[1],
            ca_public_key: params[2],
            ca_private_key: params[3],
            ca_key_managed_externally: params[4],
            created_at: params[5],
          });
        } else if (sqlUpper.startsWith('INSERT INTO TOOLS')) {
          dbInstance.data.tools.push({
            id: params[0],
            org_id: params[1],
            name: params[2],
            source_url: params[3],
            created_at: params[4],
          });
        } else if (sqlUpper.startsWith('INSERT INTO SCANS')) {
          dbInstance.data.scans.push({
            id: params[0],
            tool_id: params[1],
            tool_hash: params[2],
            manifest: params[3],
            findings: params[4],
            scanned_at: params[5],
            scanned_by: params[6],
          });
        } else if (sqlUpper.startsWith('INSERT INTO POLICIES')) {
          dbInstance.data.policies.push({
            id: params[0],
            org_id: params[1],
            name: params[2],
            rules: params[3],
            version: params[4],
            active: params[5],
            created_at: params[6],
          });
        } else if (sqlUpper.startsWith('INSERT INTO DECISIONS')) {
          dbInstance.data.decisions.push({
            id: params[0],
            scan_id: params[1],
            policy_id: params[2],
            outcome: params[3],
            reason: params[4],
            decided_at: params[5],
          });
        } else if (sqlUpper.startsWith('INSERT INTO CERTIFICATES') || sqlUpper.startsWith('INSERT OR REPLACE INTO CERTIFICATES')) {
          // Remove existing if replace
          dbInstance.data.certificates = dbInstance.data.certificates.filter((c) => c.id !== params[0]);
          dbInstance.data.certificates.push({
            id: params[0],
            decision_id: params[1],
            tool_id: params[2],
            tool_hash: params[3],
            approved_capabilities: params[4],
            risk_summary: params[5],
            issuer_org_id: params[6],
            signature: params[7],
            status: params[8],
            issued_at: params[9],
            expires_at: params[10],
            certificate_body: params[11],
          });
        } else if (sqlUpper.startsWith('INSERT INTO AUDIT_LOG')) {
          const newId = dbInstance.data.audit_log.length + 1;
          dbInstance.data.audit_log.push({
            id: newId,
            event_type: params[0],
            entity_id: params[1],
            actor: params[2],
            detail: params[3],
            prev_row_hash: params[4],
            row_hash: params[5],
            created_at: params[6],
          });
          dbInstance.save();
          return { lastInsertRowid: newId };
        } else if (sqlUpper.startsWith('INSERT INTO API_KEYS')) {
          dbInstance.data.api_keys.push({
            id: params[0],
            org_id: params[1],
            name: params[2],
            key_hash: params[3],
            key_prefix: params[4],
            created_at: params[5],
            last_used_at: params[6],
            scopes: params[7] || JSON.stringify(['*']),
            revoked_at: params[8] || null,
          });
        } else if (sqlUpper.startsWith('INSERT INTO WEBHOOK_SUBSCRIPTIONS')) {
          dbInstance.data.webhook_subscriptions.push({
            id: params[0],
            org_id: params[1],
            url: params[2],
            events: params[3],
            secret: params[4],
            created_at: params[5],
            active: params[6],
          });
        } else if (sqlUpper.startsWith('INSERT INTO WEBHOOK_DELIVERIES')) {
          dbInstance.data.webhook_deliveries.push({
            id: params[0], subscription_id: params[1], event: params[2], status: params[3],
            attempts: params[4], response_status: params[5], error: params[6], created_at: params[7],
          });
        } else if (sqlUpper.startsWith('DELETE FROM WEBHOOK_SUBSCRIPTIONS')) {
          dbInstance.data.webhook_subscriptions = dbInstance.data.webhook_subscriptions.filter(
            (sub) => sub.id !== params[0]
          );
        } else if (sqlUpper.startsWith('UPDATE API_KEYS SET LAST_USED_AT')) {
          const keyRow = dbInstance.data.api_keys.find((k) => k.id === params[1]);
          if (keyRow) {
            keyRow.last_used_at = params[0];
          }
        } else if (sqlUpper.startsWith('UPDATE API_KEYS SET REVOKED_AT')) {
          const keyRow = dbInstance.data.api_keys.find((k) => k.id === params[1]);
          if (keyRow) keyRow.revoked_at = params[0];
        } else if (sqlUpper.startsWith('UPDATE CERTIFICATES SET STATUS')) {
          // Params pattern: ("UPDATE certificates SET status = '...' WHERE id = ?", id)
          // The id is always the last (and only) runtime param
          const certId = params[params.length - 1];
          const cert = dbInstance.data.certificates.find((c) => c.id === certId);
          if (cert) {
            if (sqlUpper.includes("'REVOKED'")) cert.status = 'revoked';
            else if (sqlUpper.includes("'INVALIDATED'")) cert.status = 'invalidated';
            // Also parse the certificate_body JSON and update its status field to stay in sync
            if (cert.certificate_body) {
              try {
                const body = JSON.parse(cert.certificate_body);
                body.status = cert.status;
                cert.certificate_body = JSON.stringify(body);
              } catch (_) {}
            }
          }
        } else if (sqlUpper.startsWith('UPDATE ORGANIZATIONS SET NAME')) {
          const orgId = params[params.length - 1];
          const newName = params[0];
          const org = dbInstance.data.organizations.find((o) => o.id === orgId);
          if (org) {
            org.name = newName;
          }
        }

        dbInstance.save();
        return { lastInsertRowid: 1 };
      },

      get(...params: any[]): any {
        const sqlUpper = sql.trim().toUpperCase();

        if (sqlUpper.includes('FROM ORGANIZATIONS')) {
          if (params.length === 0) return dbInstance.data.organizations[0];
          return dbInstance.data.organizations.find((o) => o.id === params[0]);
        }
        if (sqlUpper.includes('FROM TOOLS')) {
          if (sqlUpper.includes('ORG_ID = ? AND NAME = ?')) {
            return dbInstance.data.tools.find((t) => t.org_id === params[0] && t.name === params[1]);
          }
          return dbInstance.data.tools.find((t) => t.id === params[0]);
        }
        if (sqlUpper.includes('FROM SCANS')) {
          if (sqlUpper.includes('TOOL_ID = ?')) {
            const toolScans = dbInstance.data.scans
              .filter((s) => s.tool_id === params[0])
              .sort((a, b) => new Date(b.scanned_at).getTime() - new Date(a.scanned_at).getTime());
            return toolScans[0];
          }
          return dbInstance.data.scans.find((s) => s.id === params[0]);
        }
        if (sqlUpper.includes('FROM POLICIES')) {
          if (sqlUpper.includes('WHERE ID = ?')) {
            return dbInstance.data.policies.find((p) => p.id === params[0]);
          }
          return dbInstance.data.policies.find((p) => p.active === 1 || p.active === true);
        }
        if (sqlUpper.includes('FROM DECISIONS')) {
          if (sqlUpper.includes('SCAN_ID = ?')) {
            const scanDecisions = dbInstance.data.decisions
              .filter((d) => d.scan_id === params[0])
              .sort((a, b) => new Date(b.decided_at).getTime() - new Date(a.decided_at).getTime());
            return scanDecisions[0];
          }
          return dbInstance.data.decisions.find((d) => d.id === params[0]);
        }
        if (sqlUpper.includes('FROM CERTIFICATES')) {
          return dbInstance.data.certificates.find((c) => c.id === params[0]);
        }
        if (sqlUpper.includes('FROM AUDIT_LOG')) {
          if (dbInstance.data.audit_log.length === 0) return undefined;
          return dbInstance.data.audit_log[dbInstance.data.audit_log.length - 1];
        }
        if (sqlUpper.includes('FROM API_KEYS')) {
          if (sqlUpper.includes('KEY_HASH = ?')) {
            return dbInstance.data.api_keys.find((k) => k.key_hash === params[0]);
          }
          return dbInstance.data.api_keys.find((k) => k.id === params[0]);
        }
        if (sqlUpper.includes('FROM WEBHOOK_SUBSCRIPTIONS')) {
          return dbInstance.data.webhook_subscriptions.find((s) => s.id === params[0]);
        }
        return undefined;
      },

      all(...params: any[]): any[] {
        const sqlUpper = sql.trim().toUpperCase();

        if (sqlUpper.includes('FROM AUDIT_LOG')) {
          if (sqlUpper.includes('ORDER BY ID ASC')) {
            return [...dbInstance.data.audit_log].sort((a, b) => a.id - b.id);
          }
          const limit = params[0] || 100;
          return [...dbInstance.data.audit_log].sort((a, b) => b.id - a.id).slice(0, limit);
        }

        if (sqlUpper.includes('FROM POLICIES')) {
          return dbInstance.data.policies;
        }

        if (sqlUpper.includes('FROM CERTIFICATES')) {
          // If no params passed (e.g. "SELECT * FROM certificates WHERE 1"), return all certificates
          if (params.length === 0) {
            return [...dbInstance.data.certificates].sort(
              (a, b) => new Date(b.issued_at || 0).getTime() - new Date(a.issued_at || 0).getTime()
            );
          }
          const query = (params[0] || '').replace(/%/g, '').toLowerCase();
          return dbInstance.data.certificates.filter((c) => {
            const tool = dbInstance.data.tools.find((t) => t.id === c.tool_id);
            const toolName = tool?.name?.toLowerCase() || '';
            const toolHash = c.tool_hash?.toLowerCase() || '';
            return toolName.includes(query) || toolHash.includes(query);
          });
        }


        if (sqlUpper.includes('FROM SCANS')) {
          const limit = params[0] || 50;
          return dbInstance.data.scans
            .map((s) => {
              const tool = dbInstance.data.tools.find((t) => t.id === s.tool_id);
              return { ...s, tool_name: tool?.name || 'mcp-tool' };
            })
            .sort((a, b) => new Date(b.scanned_at).getTime() - new Date(a.scanned_at).getTime())
            .slice(0, limit);
        }

        if (sqlUpper.includes('FROM API_KEYS')) {
          return dbInstance.data.api_keys.filter((k) => k.org_id === params[0]);
        }

        if (sqlUpper.includes('FROM WEBHOOK_SUBSCRIPTIONS')) {
          return dbInstance.data.webhook_subscriptions.filter((s) => s.org_id === params[0]);
        }

        if (sqlUpper.includes('FROM WEBHOOK_DELIVERIES')) {
          return dbInstance.data.webhook_deliveries.filter((d) => d.subscription_id === params[0]);
        }

        return [];
      },
    };
  }
}

export const db = new WardenDatabase();

export async function initDatabase() {
  db.exec('');

  const configuredApiKey = process.env.WARDEN_API_KEY;
  if (process.env.NODE_ENV === 'production' && (!configuredApiKey || configuredApiKey === 'warden-test-key-123' || configuredApiKey.length < 32)) {
    throw new Error('WARDEN_API_KEY must be a unique secret of at least 32 characters in production.');
  }

  // Seed default Organization if not exists
  const existingOrg = db.prepare('SELECT * FROM ORGANIZATIONS').get();
  if (!existingOrg) {
    const orgId = '0e210000-0000-4000-8000-000000000001';
    const now = new Date().toISOString();
    const keys = await generateEd25519KeyPair();

    db.prepare('INSERT INTO ORGANIZATIONS').run(
      orgId,
      'Acme Corp Security Team',
      `ed25519:${keys.publicKey}`,
      keys.privateKey,
      0,
      now
    );

    const defaultApiKey = configuredApiKey || 'warden-test-key-123';
    db.prepare('INSERT INTO api_keys').run(
      'apikey-default-v1',
      orgId,
      'default',
      createHash('sha256').update(defaultApiKey).digest('hex'),
      defaultApiKey.slice(0, 8),
      now,
        null
        , JSON.stringify(['*']), null
    );

    const defaultPolicyId = 'policy-default-v1';
    const rulesJson = JSON.stringify([
      {
        id: 'rule-injection',
        condition: "finding.type == 'prompt_injection'",
        finding_type: 'prompt_injection',
        outcome: 'block',
        reason: 'Detected prompt injection pattern in tool description.',
      },
      {
        id: 'rule-permission-mismatch',
        condition: "finding.type == 'permission_mismatch' and finding.severity == 'high'",
        finding_type: 'permission_mismatch',
        min_severity: 'high',
        outcome: 'sandbox',
        reason: 'Tool capability exceeds stated description; requires sandbox monitoring.',
      },
      {
        id: 'rule-excessive-scope',
        condition: "finding.type == 'excessive_permission' and finding.severity == 'high'",
        finding_type: 'excessive_permission',
        min_severity: 'high',
        outcome: 'sandbox',
        reason: 'Wildcard or root filesystem access requested.',
      },
      {
        id: 'rule-default-allow',
        condition: 'default',
        outcome: 'allow',
        reason: 'Matches default organizational trust policy.',
      },
    ]);

    db.prepare('INSERT INTO POLICIES').run(
      defaultPolicyId,
      orgId,
      'Standard Organizational Security Policy',
      rulesJson,
      1,
      1,
      now
    );
  } else {
    const orgRow = db.prepare('SELECT * FROM ORGANIZATIONS').get() as any;
    if (orgRow) {
      const existingKeys = db.prepare('SELECT * FROM api_keys WHERE org_id = ?').all(orgRow.id) as any[];
      if (existingKeys.length === 0) {
        const defaultApiKey = configuredApiKey || 'warden-test-key-123';
        db.prepare('INSERT INTO api_keys').run(
          'apikey-default-v1',
          orgRow.id,
          'default',
          createHash('sha256').update(defaultApiKey).digest('hex'),
          defaultApiKey.slice(0, 8),
          new Date().toISOString(),
          null
          , JSON.stringify(['*']), null
        );
      }
    }
  }
}
