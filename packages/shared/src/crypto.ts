import { createHash } from 'node:crypto';
import * as ed from '@noble/ed25519';

/**
 * RFC 8785 (JCS) compliant canonical JSON serializer.
 * Ensures deterministic string representation regardless of key insertion order.
 */
export function canonicalizeJson(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return '[' + obj.map((item) => canonicalizeJson(item)).join(',') + ']';
  }

  const keys = Object.keys(obj as Record<string, unknown>).sort();
  const pairs = keys.map((key) => {
    const val = (obj as Record<string, unknown>)[key];
    if (val === undefined) return null;
    return JSON.stringify(key) + ':' + canonicalizeJson(val);
  }).filter(Boolean);

  return '{' + pairs.join(',') + '}';
}

/**
 * Computes SHA-256 hash formatted with prefix (e.g., "sha256:<hex>")
 */
export function computeSha256(data: string | Uint8Array, rawHexOnly = false): string {
  const hash = createHash('sha256').update(data).digest('hex');
  return rawHexOnly ? hash : `sha256:${hash}`;
}

export interface Ed25519KeyPair {
  publicKey: string;  // Hex encoded
  privateKey: string; // Hex encoded
}

/**
 * Generates an Ed25519 keypair for an Organization CA.
 */
export async function generateEd25519KeyPair(): Promise<Ed25519KeyPair> {
  const privateKeyBytes = ed.utils.randomPrivateKey();
  const publicKeyBytes = await ed.getPublicKeyAsync(privateKeyBytes);
  return {
    privateKey: Buffer.from(privateKeyBytes).toString('hex'),
    publicKey: Buffer.from(publicKeyBytes).toString('hex'),
  };
}

/**
 * Signs canonical JSON data using Ed25519 private key.
 * Returns base64 signature string.
 */
export async function signCanonicalJson(dataObj: unknown, privateKeyHex: string): Promise<string> {
  const canonicalStr = canonicalizeJson(dataObj);
  const dataBytes = Buffer.from(canonicalStr, 'utf-8');
  // @noble/ed25519 requires a Uint8Array private key, not a raw hex string
  const privateKeyBytes = Uint8Array.from(Buffer.from(privateKeyHex, 'hex'));
  const signatureBytes = await ed.signAsync(dataBytes, privateKeyBytes);
  return Buffer.from(signatureBytes).toString('base64');
}

/**
 * Verifies an Ed25519 signature against canonical JSON data and public key.
 */
export async function verifyCanonicalJsonSignature(
  dataObj: unknown,
  signatureBase64: string,
  publicKeyHexOrPrefix: string
): Promise<boolean> {
  try {
    const canonicalStr = canonicalizeJson(dataObj);
    const dataBytes = Buffer.from(canonicalStr, 'utf-8');
    const signatureBytes = Buffer.from(signatureBase64, 'base64');
    
    // Clean up prefix if present (e.g. ed25519:5f3a...)
    const cleanPubKey = publicKeyHexOrPrefix.replace(/^ed25519:/, '');
    
    return await ed.verifyAsync(signatureBytes, dataBytes, cleanPubKey);
  } catch (err) {
    return false;
  }
}

/**
 * Computes next tamper-evident row hash for audit trail.
 * row_hash = sha256(prev_row_hash + canonical_json(event_data))
 */
export function computeAuditRowHash(prevRowHash: string, eventData: unknown): string {
  const eventCanonicalStr = canonicalizeJson(eventData);
  const payloadToHash = prevRowHash + eventCanonicalStr;
  return createHash('sha256').update(payloadToHash).digest('hex');
}
