import { describe, it, expect } from 'vitest';
import { hashApiKey } from './auth.js';

describe('auth service', () => {
  it('hashes API keys deterministically', () => {
    const hash1 = hashApiKey('warden-test-key-123');
    const hash2 = hashApiKey('warden-test-key-123');
    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
  });
});
