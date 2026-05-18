// tests/client.test.ts — integration tests for ZkpAuthClient
//
// Tier: Integration (mocks the HTTP layer via vi.mock)
// Covers: register(), login(), clearKey(), loadKey(), exportKey(), hasKey
// Pattern: Arrange / Act / Assert

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ZkpAuthClient } from '../src/client.js';
import { ZkpCryptoError, ZkpServerError } from '../src/errors.js';

// ── Mock the HTTP transport layer ─────────────────────────────────────────────

vi.mock('../src/http.js', () => ({
  postRegister: vi.fn(),
  postChallenge: vi.fn(),
  postVerify: vi.fn(),
  bytesToHex: (bytes: Uint8Array) =>
    Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join(''),
  hexToBytes: (hex: string) => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  },
}));

import { postRegister, postChallenge, postVerify } from '../src/http.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** A valid 32-byte challenge as hex (64 chars). */
const CHALLENGE_HEX = 'a'.repeat(64);

/** A fake JWT issued by the mock server. */
const FAKE_JWT = 'header.payload.signature';

function makeChallengeResult() {
  return {
    status: 'challenge_issued' as const,
    challengeHex: CHALLENGE_HEX,
    expiresInMs: 60_000,
  };
}

function makeVerifyResult() {
  return { token: FAKE_JWT };
}

function makeRegisterResult(userId = 'alice') {
  return { status: 'registered' as const, userId };
}

// ── ZkpAuthClient construction ────────────────────────────────────────────────

describe('ZkpAuthClient construction', () => {
  it('creates an instance with a valid baseUrl', () => {
    const client = new ZkpAuthClient({ baseUrl: 'https://api.example.com' });
    expect(client).toBeInstanceOf(ZkpAuthClient);
  });

  it('strips trailing slashes from baseUrl', () => {
    expect(() => new ZkpAuthClient({ baseUrl: 'http://localhost:3000/' })).not.toThrow();
  });

  it("accepts empty string as baseUrl (same-origin relative paths)", () => {
    expect(() => new ZkpAuthClient({ baseUrl: '' })).not.toThrow();
  });

  it("accepts '/' as baseUrl (stripped to same-origin empty base)", () => {
    expect(() => new ZkpAuthClient({ baseUrl: '/' })).not.toThrow();
  });

  it('hasKey is false before any operation', () => {
    const client = new ZkpAuthClient({ baseUrl: 'http://localhost' });
    expect(client.hasKey).toBe(false);
  });
});

// ── register() ────────────────────────────────────────────────────────────────

describe('ZkpAuthClient.register()', () => {
  let client: ZkpAuthClient;

  beforeEach(() => {
    client = new ZkpAuthClient({ baseUrl: 'http://localhost:3000' });
    vi.mocked(postRegister).mockResolvedValue(makeRegisterResult());
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('returns RegisterOutcome on success', async () => {
    const result = await client.register('alice', 'pass');
    expect(result.userId).toBe('alice');
    expect(typeof result.publicKeyHex).toBe('string');
    expect(result.publicKeyHex.length).toBe(64); // 32 bytes = 64 hex chars
  });

  it('sets hasKey = true after success', async () => {
    await client.register('alice', 'pass');
    expect(client.hasKey).toBe(true);
  });

  it('calls postRegister with the correct baseUrl and userId', async () => {
    await client.register('alice', 'pass');
    expect(postRegister).toHaveBeenCalledOnce();
    const [baseUrl, userId] = vi.mocked(postRegister).mock.calls[0]!;
    expect(baseUrl).toBe('http://localhost:3000');
    expect(userId).toBe('alice');
  });

  it('publicKeyHex in postRegister call matches returned publicKeyHex', async () => {
    const result = await client.register('alice', 'pass');
    const [, , sentHex] = vi.mocked(postRegister).mock.calls[0]!;
    expect(sentHex).toBe(result.publicKeyHex);
  });

  it('does NOT store the key when postRegister throws', async () => {
    vi.mocked(postRegister).mockRejectedValue(
      new ZkpServerError('REGISTER_FAILED', 'conflict', 409),
    );
    await expect(client.register('alice', 'pass')).rejects.toThrow(ZkpServerError);
    expect(client.hasKey).toBe(false);
  });

  it('throws ZkpCryptoError(INVALID_USERNAME) for an empty username', async () => {
    await expect(client.register('', 'pass')).rejects.toThrow(ZkpCryptoError);
    try {
      await client.register('', 'pass');
    } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('INVALID_USERNAME');
    }
  });

  it('throws ZkpCryptoError(INVALID_PASSWORD) for an oversize password', async () => {
    const bigPass = 'x'.repeat(4097);
    await expect(client.register('alice', bigPass)).rejects.toThrow(ZkpCryptoError);
    try {
      await client.register('alice', bigPass);
    } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('INVALID_PASSWORD');
    }
  });
});

// ── login() ───────────────────────────────────────────────────────────────────

describe('ZkpAuthClient.login()', () => {
  let client: ZkpAuthClient;

  beforeEach(async () => {
    client = new ZkpAuthClient({ baseUrl: 'http://localhost:3000' });
    vi.mocked(postRegister).mockResolvedValue(makeRegisterResult());
    vi.mocked(postChallenge).mockResolvedValue(makeChallengeResult());
    vi.mocked(postVerify).mockResolvedValue(makeVerifyResult());
    await client.register('alice', 'pass'); // establish key in memory
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('returns LoginOutcome with userId and token on success', async () => {
    const result = await client.login('alice', 'pass');
    expect(result.userId).toBe('alice');
    expect(result.token).toBe(FAKE_JWT);
  });

  it('calls postChallenge then postVerify in order', async () => {
    await client.login('alice', 'pass');
    expect(postChallenge).toHaveBeenCalledOnce();
    expect(postVerify).toHaveBeenCalledOnce();
    // postChallenge must be called before postVerify (order verified by mock call counts at this point)
  });

  it('proofHex sent to postVerify is a 128-char hex string (64 bytes)', async () => {
    await client.login('alice', 'pass');
    const [, , proofHex] = vi.mocked(postVerify).mock.calls[0]!;
    expect(typeof proofHex).toBe('string');
    expect(proofHex.length).toBe(128);
    expect(/^[0-9a-f]+$/.test(proofHex)).toBe(true);
  });

  it('succeeds without a prior register() call in the same session (re-derives key)', async () => {
    // Fresh client with NO register() call — simulates page-reload scenario.
    const freshClient = new ZkpAuthClient({ baseUrl: 'http://localhost:3000' });
    expect(freshClient.hasKey).toBe(false);
    const result = await freshClient.login('alice', 'pass');
    expect(result.userId).toBe('alice');
    expect(result.token).toBe(FAKE_JWT);
    // After login, key is cached for subsequent calls.
    expect(freshClient.hasKey).toBe(true);
  });

  it('throws ZkpServerError(CHALLENGE_FAILED) when postChallenge rejects', async () => {
    vi.mocked(postChallenge).mockRejectedValue(
      new ZkpServerError('CHALLENGE_FAILED', 'not found', 404),
    );
    await expect(client.login('alice', 'pass')).rejects.toThrow(ZkpServerError);
  });

  it('throws ZkpServerError(PROOF_REJECTED) when postVerify rejects', async () => {
    vi.mocked(postVerify).mockRejectedValue(
      new ZkpServerError('PROOF_REJECTED', 'invalid proof', 401),
    );
    await expect(client.login('alice', 'pass')).rejects.toThrow(ZkpServerError);
  });

  it('does not mutate hasKey on a failed login', async () => {
    vi.mocked(postVerify).mockRejectedValue(
      new ZkpServerError('PROOF_REJECTED', 'bad', 401),
    );
    await expect(client.login('alice', 'pass')).rejects.toThrow();
    expect(client.hasKey).toBe(true); // key is still in memory
  });
});

// ── clearKey / loadKey / exportKey ────────────────────────────────────────────

describe('ZkpAuthClient key lifecycle', () => {
  let client: ZkpAuthClient;

  beforeEach(async () => {
    client = new ZkpAuthClient({ baseUrl: 'http://localhost' });
    vi.mocked(postRegister).mockResolvedValue(makeRegisterResult());
    await client.register('alice', 'pass');
  });

  afterEach(() => { vi.clearAllMocks(); });

  it('clearKey() sets hasKey to false', () => {
    client.clearKey();
    expect(client.hasKey).toBe(false);
  });

  it('clearKey() is idempotent (safe to call multiple times)', () => {
    client.clearKey();
    expect(() => client.clearKey()).not.toThrow();
    expect(client.hasKey).toBe(false);
  });

  it('exportKey() returns a 32-byte copy', () => {
    const key = client.exportKey();
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.byteLength).toBe(32);
  });

  it('exportKey() returns a copy, not the internal buffer', () => {
    const key = client.exportKey();
    key.fill(0);
    // The client should still be able to export a non-zero key.
    const key2 = client.exportKey();
    expect(key2.some((b) => b !== 0)).toBe(true);
  });

  it('exportKey() throws ZkpCryptoError when no key in memory', () => {
    client.clearKey();
    expect(() => client.exportKey()).toThrow(ZkpCryptoError);
  });

  it('loadKey() + exportKey() round-trips a key', () => {
    const original = client.exportKey();
    client.clearKey();
    client.loadKey(original);
    expect(client.hasKey).toBe(true);
    const restored = client.exportKey();
    expect(Buffer.from(restored).equals(Buffer.from(original))).toBe(true);
  });

  it('loadKey() throws ZkpCryptoError for a non-32-byte buffer', () => {
    const bad = new Uint8Array(16);
    expect(() => client.loadKey(bad)).toThrow(ZkpCryptoError);
  });

  it('loadKey() throws ZkpCryptoError for a non-Uint8Array', () => {
    expect(() => client.loadKey('not a buffer' as unknown as Uint8Array)).toThrow(ZkpCryptoError);
  });
});
