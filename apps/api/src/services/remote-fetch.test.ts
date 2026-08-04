import { describe, expect, it } from 'vitest';
import { fetchPublicJson } from './remote-fetch.js';

describe('fetchPublicJson', () => {
  it('rejects insecure and private-network targets before fetching', async () => {
    await expect(fetchPublicJson('http://example.com/manifest.json')).rejects.toThrow('HTTPS');
    await expect(fetchPublicJson('https://127.0.0.1/manifest.json')).rejects.toThrow('private or reserved');
  });
});
