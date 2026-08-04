import fs from 'node:fs';
import { computeSha256 } from '@warden/shared';
import { CertificateCache } from './cache.js';
import { APIError, AuthError, ToolNotTrustedError } from './errors.js';
import type {
  CertificateVerification,
  ApiKeyRecord,
  CreatedApiKey,
  HealthResponse,
  VerifyResponse,
  WebhookSubscription,
  WebhookDelivery,
  WardenClientOptions,
  WardenCertificate,
} from './types.js';

export class Warden {
  private apiKey: string;
  private baseUrl: string;
  private cache: CertificateCache;
  private timeoutMs: number;

  constructor(options: WardenClientOptions = {}) {
    this.apiKey = options.apiKey || process.env.WARDEN_API_KEY || '';
    this.baseUrl = (options.baseUrl || process.env.WARDEN_API_URL || 'http://localhost:3000').replace(/\/$/, '');
    this.cache = new CertificateCache(options.cacheDir, options.cacheTtlMs);
    this.timeoutMs = options.timeoutMs ?? 15_000;
  }

  private headers(): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.apiKey) {
      headers.Authorization = `Bearer ${this.apiKey}`;
    }
    return headers;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: this.headers(),
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw new APIError(`Failed to connect to Warden API at ${this.baseUrl}: ${(error as Error).message}`);
    }

    if (response.status === 401) {
      throw new AuthError();
    }
    if (!response.ok) {
      const text = await response.text();
      throw new APIError(`Warden API returned status ${response.status}: ${text}`, response.status);
    }

    return (await response.json()) as T;
  }

  private computeManifestHash(toolUrl: string): string | undefined {
    try {
      if (fs.existsSync(toolUrl)) {
        const content = fs.readFileSync(toolUrl, 'utf-8');
        return computeSha256(content);
      }
    } catch {
      return undefined;
    }
    return undefined;
  }

  async verify(toolUrl: string): Promise<VerifyResponse> {
    const manifestHash = this.computeManifestHash(toolUrl);
    const cached = this.cache.get(toolUrl);

    if (cached) {
      const offlineResult = await this.cache.verifyOffline(cached, manifestHash);
      if (offlineResult && offlineResult.decision === 'allow') {
        return offlineResult;
      }
    }

    const result = await this.request<VerifyResponse>('POST', '/v1/certificates/verify', { tool_url: toolUrl });

    if (result.decision === 'allow' && result.certificate_id) {
      try {
        const cert = await this.getCertificate(result.certificate_id);
        this.cache.set(toolUrl, cert);
      } catch {
        // caching is best-effort
      }
    } else if (result.decision === 'block') {
      this.cache.invalidate(toolUrl);
    }

    return result;
  }

  /** Verifies a tool and raises a typed error whenever policy does not allow it. */
  async verifyOrThrow(toolUrl: string): Promise<VerifyResponse> {
    const result = await this.verify(toolUrl);
    if (result.decision !== 'allow') {
      throw new ToolNotTrustedError(result.reason);
    }
    return result;
  }

  async scan(toolUrl: string): Promise<unknown> {
    let manifest: unknown;
    let toolName = 'mcp-tool';

    if (fs.existsSync(toolUrl)) {
      manifest = JSON.parse(fs.readFileSync(toolUrl, 'utf-8'));
      toolName = (manifest as any).name || 'mcp-tool';
    } else {
      const res = await fetch(toolUrl);
      if (!res.ok) {
        throw new APIError(`Failed to fetch manifest: HTTP ${res.status}`);
      }
      manifest = await res.json();
      toolName = (manifest as any).name || 'remote-mcp-tool';
    }

    return this.request('POST', '/v1/scans', {
      tool_name: toolName,
      source_url: toolUrl,
      manifest,
      actor: 'sdk:client',
    });
  }

  async getCertificate(certificateId: string): Promise<WardenCertificate> {
    return this.request<WardenCertificate>('GET', `/v1/certificates/${certificateId}`);
  }

  async verifyCertificate(certificateId: string, currentHash?: string): Promise<CertificateVerification> {
    return this.request<CertificateVerification>('POST', `/v1/certificates/${certificateId}/verify`,
      currentHash ? { current_hash: currentHash } : {});
  }

  async revokeCertificate(certificateId: string, reason?: string): Promise<{ revoked: true; id: string; status: 'revoked' }> {
    return this.request('POST', `/v1/certificates/${certificateId}/revoke`, reason ? { reason } : {});
  }

  async health(): Promise<HealthResponse> {
    return this.request<HealthResponse>('GET', '/v1/health');
  }

  async listWebhooks(): Promise<WebhookSubscription[]> {
    return this.request<WebhookSubscription[]>('GET', '/v1/webhooks');
  }

  async registerWebhook(url: string, events: string[] = ['cert_revoked']): Promise<WebhookSubscription> {
    return this.request<WebhookSubscription>('POST', '/v1/webhooks', { url, events });
  }

  async deleteWebhook(webhookId: string): Promise<{ deleted: true; id: string }> {
    return this.request('DELETE', `/v1/webhooks/${webhookId}`);
  }

  async listWebhookDeliveries(webhookId: string): Promise<WebhookDelivery[]> {
    return this.request<WebhookDelivery[]>('GET', `/v1/webhooks/${webhookId}/deliveries`);
  }

  async listApiKeys(): Promise<ApiKeyRecord[]> {
    return this.request<ApiKeyRecord[]>('GET', '/v1/api-keys');
  }

  /** The plaintext key is returned only by this method. Store it outside source control. */
  async createApiKey(name: string, scopes: string[] = ['verify:read']): Promise<CreatedApiKey> {
    return this.request<CreatedApiKey>('POST', '/v1/api-keys', { name, scopes });
  }

  async revokeApiKey(keyId: string): Promise<{ revoked: true; id: string }> {
    return this.request('POST', `/v1/api-keys/${keyId}/revoke`);
  }

  handleRevocationEvent(certificateId: string): void {
    this.cache.invalidateByCertificateId(certificateId);
  }
}

export { CertificateCache } from './cache.js';
export { WardenError, ToolNotTrustedError, AuthError, APIError } from './errors.js';
export type {
  CertificateVerification,
  ApiKeyRecord,
  CreatedApiKey,
  HealthResponse,
  WardenClientOptions,
  VerifyResponse,
  WebhookSubscription,
  WebhookDelivery,
  WardenCertificate,
} from './types.js';
