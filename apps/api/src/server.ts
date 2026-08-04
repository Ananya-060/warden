import Fastify from 'fastify';
import cors from '@fastify/cors';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { initDatabase, db } from './db/index.js';
import { InspectorService } from './services/inspector.js';
import { PolicyEngineService } from './services/policy-engine.js';
import { CertificateAuthorityService } from './services/ca.js';
import { AuditLogService } from './services/audit-log.js';
import { WardenCertificate, verifyCanonicalJsonSignature } from '@warden/shared';

import { seedRealWorldMCPTools } from './services/seed.js';
import { verifyToolByUrl } from './services/verify-tool.js';
import { authenticateBearerToken, createApiKey, hasScope, listApiKeys, revokeApiKey } from './services/auth.js';
import { WebhookService } from './services/webhooks.js';

// Initialize DB schema & default seeds
await initDatabase();
await seedRealWorldMCPTools();

const server = Fastify({ logger: true });

const corsOrigin = process.env.WARDEN_CORS_ORIGIN || (process.env.NODE_ENV === 'production' ? false : '*');
await server.register(cors, { origin: corsOrigin });

await server.register(swagger, {
  swagger: {
    info: {
      title: 'Warden Core API',
      description: 'Portable Trust Infrastructure for AI Tools',
      version: '1.0.0',
    },
  },
});

await server.register(swaggerUi, {
  routePrefix: '/docs',
});

const PROTECTED_PREFIXES = ['/v1/certificates/verify', '/v1/webhooks', '/v1/api-keys'];

server.addHook('onRequest', async (request, reply) => {
  const path = request.url.split('?')[0];
  const requiresAuth = PROTECTED_PREFIXES.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));

  const authHeader = request.headers.authorization;
  if (!requiresAuth && !authHeader) {
    return;
  }

  const auth = authenticateBearerToken(authHeader);
  if (!auth) {
    return reply.status(401).send({ error: 'Invalid or missing API Key' });
  }

  (request as any).wardenAuth = auth;
});

function requireScope(request: any, reply: any, scope: string): boolean {
  const auth = request.wardenAuth;
  if (!auth || !hasScope(auth, scope)) {
    reply.status(auth ? 403 : 401).send({ error: auth ? `API key lacks required scope '${scope}'.` : 'Invalid or missing API Key' });
    return false;
  }
  return true;
}

// Health check
server.get('/v1/health', async () => {
  const auditIntegrity = AuditLogService.verifyChainIntegrity();
  return {
    status: 'ok',
    audit_chain: auditIntegrity,
    timestamp: new Date().toISOString(),
  };
});

// 1. Submit a tool for inspection
server.post('/v1/scans', async (request, reply) => {
  if ((request as any).wardenAuth && !requireScope(request, reply, 'scan:write')) return;
  const body = request.body as any;
  if (!body || !body.tool_name || !body.manifest) {
    return reply.status(400).send({ error: "Missing required fields 'tool_name' and 'manifest'." });
  }

  try {
    const result = await InspectorService.inspectTool({
      tool_name: body.tool_name,
      source_url: body.source_url,
      manifest: body.manifest,
      org_id: (request as any).wardenAuth?.orgId,
      actor: (request as any).wardenAuth?.actor || body.actor || 'api-caller',
    });
    return reply.status(201).send(result);
  } catch (err) {
    return reply.status(400).send({ error: (err as Error).message });
  }
});

// 2. Fetch past scan
server.get('/v1/scans/:id', async (request, reply) => {
  const { id } = request.params as { id: string };
  const scanRow = db.prepare('SELECT * FROM scans WHERE id = ?').get(id) as any;

  if (!scanRow) {
    return reply.status(404).send({ error: `Scan '${id}' not found.` });
  }

  return {
    id: scanRow.id,
    tool_id: scanRow.tool_id,
    tool_hash: scanRow.tool_hash,
    manifest: JSON.parse(scanRow.manifest),
    findings: JSON.parse(scanRow.findings),
    scanned_at: scanRow.scanned_at,
    scanned_by: scanRow.scanned_by,
  };
});

// 3. Evaluate scan against policy -> Decision
server.post('/v1/decisions', async (request, reply) => {
  if ((request as any).wardenAuth && !requireScope(request, reply, 'decision:write')) return;
  const body = request.body as any;
  if (!body || !body.scan_id) {
    return reply.status(400).send({ error: "Missing required field 'scan_id'." });
  }

  try {
    const decision = PolicyEngineService.evaluateScan(body.scan_id, body.policy_id, (request as any).wardenAuth?.actor || body.actor);
    return reply.status(201).send(decision);
  } catch (err) {
    return reply.status(400).send({ error: (err as Error).message });
  }
});

// 4. Issue Trust Certificate
server.post('/v1/certificates', async (request, reply) => {
  if ((request as any).wardenAuth && !requireScope(request, reply, 'certificate:write')) return;
  const body = request.body as any;
  if (!body || !body.decision_id) {
    return reply.status(400).send({ error: "Missing required field 'decision_id'." });
  }

  try {
    const cert = await CertificateAuthorityService.issueCertificate(body.decision_id, (request as any).wardenAuth?.actor || body.actor);
    return reply.status(201).send(cert);
  } catch (err) {
    return reply.status(400).send({ error: (err as Error).message });
  }
});

// Helper: parse a raw certificate DB row, handling legacy records where
// certificate_body was accidentally stored in expires_at
function parseCertRow(r: any): WardenCertificate | null {
  try {
    const bodyStr: string | undefined =
      r.certificate_body ??
      (typeof r.expires_at === 'string' && r.expires_at.startsWith('{') ? r.expires_at : undefined);
    if (!bodyStr) return null;
    const cert: WardenCertificate = JSON.parse(bodyStr);
    // For new records r.status is 'active'/'revoked'; for old records it's a timestamp string
    if (r.status && !r.status.startsWith('20')) {
      cert.status = r.status;
    }
    return cert;
  } catch {
    return null;
  }
}

// 5. Get Certificate
server.get('/v1/certificates/:id', async (request, reply) => {
  const { id } = request.params as { id: string };
  const certRow = db.prepare('SELECT * FROM certificates WHERE id = ?').get(id) as any;

  if (!certRow) {
    return reply.status(404).send({ error: `Certificate '${id}' not found.` });
  }

  const cert = parseCertRow(certRow);
  if (!cert) {
    return reply.status(500).send({ error: 'Certificate record is malformed.' });
  }
  return cert;
});

// 6. Verify tool by URL (SDK / pipeline entry point — must be registered before :id routes)
server.post('/v1/certificates/verify', async (request, reply) => {
  if (!requireScope(request, reply, 'verify:read')) return;
  const body = request.body as any;
  if (!body?.tool_url) {
    return reply.status(400).send({ error: "Missing required field 'tool_url'." });
  }

  const auth = (request as any).wardenAuth;
  try {
    const result = await verifyToolByUrl(body.tool_url, auth?.actor || 'api:verify');
    return result;
  } catch (err) {
    return reply.status(400).send({ error: (err as Error).message });
  }
});

// 7. Verify Certificate (by certificate ID + optional hash)
server.post('/v1/certificates/:id/verify', async (request, reply) => {
  const { id } = request.params as { id: string };
  const body = (request.body as any) || {};

  const certRow = db.prepare('SELECT * FROM certificates WHERE id = ?').get(id) as any;
  if (!certRow) {
    return reply.status(404).send({ error: `Certificate '${id}' not found.` });
  }

  const cert = parseCertRow(certRow);
  if (!cert) {
    return reply.status(500).send({ error: 'Certificate record is malformed.' });
  }

  const result = await CertificateAuthorityService.verifyCertificate(cert, body.current_hash);
  return result;
});

// 8. Import Certificate Bundle
server.post('/v1/certificates/import', async (request, reply) => {
  const cert = request.body as WardenCertificate;
  if (!cert || !cert.certificate_id || !cert.signature || !cert.issuer) {
    return reply.status(400).send({ error: 'Invalid certificate format.' });
  }

  const verification = await CertificateAuthorityService.verifyCertificate(cert);
  if (!verification.signature_valid) {
    return reply.status(400).send({ error: 'Certificate signature verification failed.' });
  }

  // Save imported certificate into registry
  const now = new Date().toISOString();
  db.prepare(
    `INSERT OR REPLACE INTO certificates 
     (id, decision_id, tool_id, tool_hash, approved_capabilities, risk_summary, issuer_org_id, signature, status, issued_at, expires_at, certificate_body)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    cert.certificate_id,
    'imported-decision',
    'imported-tool-' + cert.tool.name,
    cert.tool.hash,
    JSON.stringify(cert.approved_capabilities),
    JSON.stringify(cert.risk_summary),
    cert.issuer.org_id,
    cert.signature,
    cert.status || 'active',
    cert.issued_at,
    cert.expires_at,
    JSON.stringify(cert)
  );

  AuditLogService.logEvent({
    event_type: 'cert_imported',
    entity_id: cert.certificate_id,
    actor: 'api-caller',
    detail: {
      tool_name: cert.tool.name,
      issuer_org: cert.issuer.org_name,
      status: cert.status,
    },
  });

  return { imported: true, certificate: cert, verification };
});

// 8. Revoke Certificate
server.post('/v1/certificates/:id/revoke', async (request, reply) => {
  if ((request as any).wardenAuth && !requireScope(request, reply, 'certificate:write')) return;
  const { id } = request.params as { id: string };
  const body = (request.body as any) || {};

  const certRow = db.prepare('SELECT * FROM certificates WHERE id = ?').get(id) as any;
  if (!certRow) {
    return reply.status(404).send({ error: `Certificate '${id}' not found.` });
  }

  db.prepare("UPDATE certificates SET status = 'revoked' WHERE id = ?").run(id);

  AuditLogService.logEvent({
    event_type: 'cert_revoked',
    entity_id: id,
    actor: (request as any).wardenAuth?.actor || body.actor || 'admin',
    detail: { reason: body.reason || 'Manual revocation by administrator' },
  });

  const orgRow = db.prepare('SELECT * FROM ORGANIZATIONS').get() as any;
  if (orgRow) {
    WebhookService.fanOut('cert_revoked', orgRow.id, {
      certificate_id: id,
      reason: body.reason || 'Manual revocation by administrator',
    }).catch((err) => server.log.warn({ err }, 'Webhook fan-out failed'));
  }

  return { revoked: true, id, status: 'revoked' };
});

// API key management. The plaintext key is only returned from POST once.
server.get('/v1/api-keys', async (request, reply) => {
  if (!requireScope(request, reply, 'keys:manage')) return;
  return listApiKeys((request as any).wardenAuth.orgId);
});

server.post('/v1/api-keys', async (request, reply) => {
  if (!requireScope(request, reply, 'keys:manage')) return;
  const body = request.body as { name?: string; scopes?: string[] };
  if (!body?.name || body.name.length > 100) return reply.status(400).send({ error: "Provide a 'name' of at most 100 characters." });
  const scopes = body.scopes || ['verify:read'];
  const allowedScopes = new Set(['verify:read', 'scan:write', 'decision:write', 'certificate:write', 'webhook:manage', 'keys:manage']);
  if (!Array.isArray(scopes) || scopes.some((scope) => !allowedScopes.has(scope))) {
    return reply.status(400).send({ error: 'One or more API key scopes are invalid.' });
  }
  const key = createApiKey((request as any).wardenAuth.orgId, body.name, scopes);
  AuditLogService.logEvent({ event_type: 'api_key_created', entity_id: key.id, actor: (request as any).wardenAuth.actor, detail: { name: key.name, scopes } });
  return reply.status(201).send(key);
});

server.post('/v1/api-keys/:id/revoke', async (request, reply) => {
  if (!requireScope(request, reply, 'keys:manage')) return;
  const { id } = request.params as { id: string };
  if (!revokeApiKey((request as any).wardenAuth.orgId, id)) return reply.status(404).send({ error: `API key '${id}' not found or already revoked.` });
  AuditLogService.logEvent({ event_type: 'api_key_revoked', entity_id: id, actor: (request as any).wardenAuth.actor, detail: {} });
  return { revoked: true, id };
});

// 9. Policy CRUD & Simulation
server.get('/v1/policies', async () => {
  const rows = db.prepare('SELECT * FROM policies ORDER BY created_at DESC').all() as any[];
  return rows.map((r) => ({ ...r, rules: JSON.parse(r.rules) }));
});

server.post('/v1/policies/:id/simulate', async (request, reply) => {
  const body = request.body as any;
  if (!body || !body.rules) {
    return reply.status(400).send({ error: "Missing required field 'rules' (YAML/JSON policy string)." });
  }

  try {
    const sim = PolicyEngineService.simulatePolicy(body.rules, body.limit || 50);
    return sim;
  } catch (err) {
    return reply.status(400).send({ error: (err as Error).message });
  }
});

// 10. Audit Log Endpoint
server.get('/v1/audit-log', async (request) => {
  const query = request.query as any;
  const limit = query.limit ? parseInt(query.limit, 10) : 100;
  const logs = AuditLogService.getLogs(limit);
  const integrity = AuditLogService.verifyChainIntegrity();

  return {
    integrity,
    logs,
  };
});

// 11. Registry Search Endpoint
server.get('/v1/registry/search', async (request) => {
  const query = (request.query as any).q || '';
  const rows = db
    .prepare(
      `SELECT c.*, t.name as tool_name, t.source_url 
       FROM certificates c 
       LEFT JOIN tools t ON c.tool_id = t.id 
       WHERE t.name LIKE ? OR c.tool_hash LIKE ?
       ORDER BY c.issued_at DESC`
    )
    .all(`%${query}%`, `%${query}%`) as any[];

  return rows.map(parseCertRow).filter(Boolean);
});

// 12. Stats Endpoint - rich dashboard metrics
server.get('/v1/stats', async () => {
  const allCerts = db.prepare('SELECT * FROM certificates WHERE 1').all() as any[];
  const allScans = db.prepare('SELECT s.*, t.name as tool_name FROM scans s JOIN tools t ON s.tool_id = t.id ORDER BY s.scanned_at DESC LIMIT 100').all() as any[];
  const auditIntegrity = AuditLogService.verifyChainIntegrity();
  const allLogs = AuditLogService.getLogs(200);

  // Build risk distribution from recent scans
  const riskDistribution = { none: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const scan of allScans) {
    const findings = JSON.parse(scan.findings || '[]');
    if (findings.length === 0) {
      riskDistribution.none++;
    } else {
      const severities = findings.map((f: any) => f.severity);
      if (severities.includes('critical')) riskDistribution.critical++;
      else if (severities.includes('high')) riskDistribution.high++;
      else if (severities.includes('medium')) riskDistribution.medium++;
      else riskDistribution.low++;
    }
  }

  // Recent activity feed (last 10 audit events)
  const recentActivity = allLogs.slice(0, 10).map((log: any) => ({
    id: log.id,
    event_type: log.event_type,
    actor: log.actor,
    entity_id: log.entity_id,
    created_at: log.created_at,
  }));

  // Cert status breakdown
  const certStats = {
    active: allCerts.filter((c) => c.status === 'active').length,
    revoked: allCerts.filter((c) => c.status === 'revoked').length,
    invalidated: allCerts.filter((c) => c.status === 'invalidated').length,
    expired: allCerts.filter((c) => c.status === 'expired').length,
    total: allCerts.length,
  };

  // Event type breakdown from audit log
  const eventCounts: Record<string, number> = {};
  for (const log of allLogs) {
    eventCounts[log.event_type] = (eventCounts[log.event_type] || 0) + 1;
  }

  return {
    totalTools: (db.prepare('SELECT * FROM certificates WHERE 1').all() as any[]).length,
    activeCertificates: certStats.active,
    totalScans: allScans.length,
    auditIntegrityValid: auditIntegrity.valid,
    recentLogsCount: allLogs.length,
    riskDistribution,
    certStats,
    recentActivity,
    eventCounts,
  };
});

// 13. Tools list endpoint
server.get('/v1/tools', async (request) => {
  const query = (request.query as any).q || '';
  const limit = parseInt((request.query as any).limit || '50', 10);
  const allScans = db.prepare(
    'SELECT s.*, t.name as tool_name FROM scans s JOIN tools t ON s.tool_id = t.id ORDER BY s.scanned_at DESC LIMIT ?'
  ).all(limit) as any[];

  const filtered = query
    ? allScans.filter((s: any) => s.tool_name.toLowerCase().includes(query.toLowerCase()))
    : allScans;

  return filtered.map((s: any) => ({
    scan_id: s.id,
    tool_id: s.tool_id,
    tool_name: s.tool_name,
    tool_hash: s.tool_hash,
    findings_count: JSON.parse(s.findings || '[]').length,
    scanned_at: s.scanned_at,
    scanned_by: s.scanned_by,
  }));
});

// 14. Organization info endpoint
server.get('/v1/organization', async () => {
  const orgRow = db.prepare('SELECT * FROM ORGANIZATIONS').get() as any;
  if (!orgRow) return { error: 'No organization found' };
  return {
    id: orgRow.id,
    name: orgRow.name,
    ca_public_key: orgRow.ca_public_key,
    ca_key_managed_externally: orgRow.ca_key_managed_externally,
    created_at: orgRow.created_at,
  };
});

// 15. Update organization name
server.patch('/v1/organization', async (request, reply) => {
  const body = request.body as any;
  const orgRow = db.prepare('SELECT * FROM ORGANIZATIONS').get() as any;
  if (!orgRow) return reply.status(404).send({ error: 'No organization found' });

  if (body?.name) {
    orgRow.name = body.name;
    // Persist via audit log as we can't do raw SQL UPDATE on this JSON DB
    AuditLogService.logEvent({
      event_type: 'org_updated',
      entity_id: orgRow.id,
      actor: body.actor || 'admin',
      detail: { updated_name: body.name },
    });
    // Update org name directly in the DB data
    const allOrgs = (db as any).data?.organizations;
    if (allOrgs) {
      const org = allOrgs.find((o: any) => o.id === orgRow.id);
      if (org) { org.name = body.name; (db as any).save(); }
    }
  }

  return { updated: true, name: body.name };
});

// 16. Webhook subscription management (SDK consumers register for revocation events)
server.get('/v1/webhooks', async (request, reply) => {
  if (!requireScope(request, reply, 'webhook:manage')) return;
  const auth = (request as any).wardenAuth;
  return WebhookService.listSubscriptions(auth.orgId);
});

server.post('/v1/webhooks', async (request, reply) => {
  if (!requireScope(request, reply, 'webhook:manage')) return;
  const auth = (request as any).wardenAuth;

  const body = request.body as any;
  if (!body?.url) {
    return reply.status(400).send({ error: "Missing required field 'url'." });
  }

  const subscription = WebhookService.createSubscription(auth.orgId, body.url, body.events);
  return reply.status(201).send(subscription);
});

server.delete('/v1/webhooks/:id', async (request, reply) => {
  if (!requireScope(request, reply, 'webhook:manage')) return;
  const auth = (request as any).wardenAuth;

  const { id } = request.params as { id: string };
  const deleted = WebhookService.deleteSubscription(id, auth.orgId);
  if (!deleted) {
    return reply.status(404).send({ error: `Webhook subscription '${id}' not found.` });
  }
  return { deleted: true, id };
});

server.get('/v1/webhooks/:id/deliveries', async (request, reply) => {
  if (!requireScope(request, reply, 'webhook:manage')) return;
  const { id } = request.params as { id: string };
  const deliveries = WebhookService.listDeliveries(id, (request as any).wardenAuth.orgId);
  if (!deliveries) return reply.status(404).send({ error: `Webhook subscription '${id}' not found.` });
  return deliveries;
});

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = '0.0.0.0';

try {
  await server.listen({ port: PORT, host: HOST });
  console.log(`🛡️ Warden Core API running at http://localhost:${PORT}`);
  console.log(`📖 API Documentation at http://localhost:${PORT}/docs`);
} catch (err) {
  server.log.error(err);
  process.exit(1);
}
