import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { db } from '../db/index.js';

export interface AuthenticatedContext {
  orgId: string;
  apiKeyId: string;
  actor: string;
  scopes: string[];
}

export function hashApiKey(rawKey: string): string {
  return createHash('sha256').update(rawKey).digest('hex');
}

export function authenticateBearerToken(authHeader: string | undefined): AuthenticatedContext | null {
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }

  const rawKey = authHeader.slice('Bearer '.length).trim();
  if (!rawKey) {
    return null;
  }

  const keyHash = hashApiKey(rawKey);
  const keyRow = db.prepare('SELECT * FROM api_keys WHERE key_hash = ?').get(keyHash) as any;

  if (!keyRow || keyRow.revoked_at) {
    return null;
  }

  db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(new Date().toISOString(), keyRow.id);

  return {
    orgId: keyRow.org_id,
    apiKeyId: keyRow.id,
    actor: `api-key:${keyRow.name}`,
    scopes: JSON.parse(keyRow.scopes || '["*"]'),
  };
}

export function hasScope(auth: AuthenticatedContext, scope: string): boolean {
  return auth.scopes.includes('*') || auth.scopes.includes(scope);
}

export function createApiKey(orgId: string, name: string, scopes: string[] = ['verify:read']): { id: string; key: string; name: string; scopes: string[]; created_at: string } {
  const key = `wrd_${randomBytes(32).toString('base64url')}`;
  const id = randomUUID();
  const createdAt = new Date().toISOString();
  db.prepare('INSERT INTO api_keys').run(id, orgId, name, hashApiKey(key), key.slice(0, 12), createdAt, null, JSON.stringify(scopes), null);
  return { id, key, name, scopes, created_at: createdAt };
}

export function listApiKeys(orgId: string) {
  return (db.prepare('SELECT * FROM api_keys WHERE org_id = ?').all(orgId) as any[]).map((key) => ({
    id: key.id,
    name: key.name,
    key_prefix: key.key_prefix,
    scopes: JSON.parse(key.scopes || '["*"]'),
    created_at: key.created_at,
    last_used_at: key.last_used_at || null,
    revoked_at: key.revoked_at || null,
  }));
}

export function revokeApiKey(orgId: string, keyId: string): boolean {
  const key = db.prepare('SELECT * FROM api_keys WHERE id = ?').get(keyId) as any;
  if (!key || key.org_id !== orgId || key.revoked_at) return false;
  db.prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ?').run(new Date().toISOString(), keyId);
  return true;
}

export function seedDefaultApiKey(orgId: string): string {
  const defaultKey = process.env.WARDEN_API_KEY || 'warden-test-key-123';
  const existing = db.prepare('SELECT * FROM api_keys WHERE org_id = ?').all(orgId) as any[];

  if (existing.length > 0) {
    return defaultKey;
  }

  const now = new Date().toISOString();
  const keyId = 'apikey-default-v1';

  db.prepare('INSERT INTO api_keys').run(
    keyId,
    orgId,
    'default',
    hashApiKey(defaultKey),
    defaultKey.slice(0, 8),
    now,
    null
    , JSON.stringify(['*']), null
  );

  return defaultKey;
}
