import { afterEach, describe, expect, it, vi } from 'vitest';
import { Warden, APIError, ToolNotTrustedError } from './index.js';

describe('Warden SDK client', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends bearer auth and serializes verification requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      decision: 'allow', reason: 'Certified', certificate_id: null, risk_score: 0,
    }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const client = new Warden({ apiKey: 'test-key', baseUrl: 'https://api.example.test' });
    await client.verify('https://tools.example.test/manifest.json');

    expect(fetchMock).toHaveBeenCalledWith(
      'https://api.example.test/v1/certificates/verify',
      expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer test-key' }) })
    );
  });

  it('fails closed with ToolNotTrustedError', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      decision: 'block', reason: 'No certificate found', certificate_id: null, risk_score: 0,
    }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const client = new Warden({ apiKey: 'test-key', baseUrl: 'https://api.example.test' });
    await expect(client.verifyOrThrow('https://tools.example.test/manifest.json')).rejects.toBeInstanceOf(ToolNotTrustedError);
  });

  it('preserves the API status on request errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('bad request', { status: 400 })));
    const client = new Warden({ apiKey: 'test-key', baseUrl: 'https://api.example.test' });
    await expect(client.health()).rejects.toMatchObject({ status: 400 } satisfies Partial<APIError>);
  });
});
