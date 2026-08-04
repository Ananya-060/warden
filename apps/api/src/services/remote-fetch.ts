import dns from 'node:dns/promises';
import net from 'node:net';

const MAX_MANIFEST_BYTES = 1_000_000;

function isPrivateAddress(address: string): boolean {
  if (net.isIP(address) === 4) {
    const [a, b] = address.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || a >= 224 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168);
  }
  const normalized = address.toLowerCase();
  return normalized === '::1' || normalized === '::' || normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe80:');
}

/** Fetches a public JSON manifest without allowing redirects or internal-network access. */
export async function fetchPublicJson(urlString: string): Promise<Record<string, unknown>> {
  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    throw new Error('Invalid tool_url. Must be an HTTPS URL or a local file path.');
  }

  if (url.protocol !== 'https:' || url.username || url.password || url.port) {
    throw new Error('Remote tool manifests must use HTTPS without credentials or a custom port.');
  }

  const addresses = await dns.lookup(url.hostname, { all: true });
  if (addresses.some(({ address }) => isPrivateAddress(address))) {
    throw new Error('Remote tool manifest resolves to a private or reserved network address.');
  }

  const response = await fetch(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(5_000),
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) throw new Error(`Failed to fetch tool manifest from URL: HTTP ${response.status}`);

  const contentLength = Number(response.headers.get('content-length') || '0');
  if (contentLength > MAX_MANIFEST_BYTES) throw new Error('Tool manifest exceeds the 1 MB size limit.');

  const text = await response.text();
  if (Buffer.byteLength(text, 'utf8') > MAX_MANIFEST_BYTES) throw new Error('Tool manifest exceeds the 1 MB size limit.');
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new Error('Remote tool manifest is not valid JSON.');
  }
}
