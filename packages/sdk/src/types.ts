import type { VerifyResponse, WardenCertificate } from '@warden/shared';

export interface WardenClientOptions {
  apiKey?: string;
  baseUrl?: string;
  cacheDir?: string;
  cacheTtlMs?: number;
  timeoutMs?: number;
}

export interface CachedCertificateEntry {
  certificate: WardenCertificate;
  cachedAt: string;
  toolUrl: string;
}

export type { VerifyResponse, WardenCertificate };

export interface HealthResponse {
  status: 'ok';
  audit_chain: { valid: boolean; total_rows: number; invalid_at_id?: number; reason?: string };
  timestamp: string;
}

export interface CertificateVerification {
  signature_valid: boolean;
  hash_matched: boolean;
  valid: boolean;
  status: string;
  reason: string;
}

export interface WebhookSubscription {
  id: string;
  org_id: string;
  url: string;
  events: string[];
  secret?: string;
  created_at: string;
  active: boolean;
}

export interface ApiKeyRecord {
  id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface CreatedApiKey extends Omit<ApiKeyRecord, 'key_prefix' | 'last_used_at' | 'revoked_at'> {
  key: string;
}

export interface WebhookDelivery {
  id: string;
  subscription_id: string;
  event: string;
  status: 'delivered' | 'failed';
  attempts: number;
  response_status: number | null;
  error: string | null;
  created_at: string;
}
