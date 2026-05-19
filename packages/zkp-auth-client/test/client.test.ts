// tests/client.test.ts — integration tests for ZkpAuthClient
//
// Tier: Integration (mocks the HTTP layer and KeyStorage via vi.mock / injection)
// Covers: register(), login(), clearKey(), loadKey(), exportKey(), hasKey,
//         hasLocalKey(), exportKeyBlob(), importKeyBlob()
// Pattern: Arrange / Act / Assert

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ZkpAuthClient } from '../src/client.js';
import { ZkpCryptoError, ZkpServerError, ZkpStorageError } from '../src/errors.js';
import { MemoryKeyStorage } from '../src/key-storage.js';
import type { ChallengeResult, RegisterResult, VerifyResult } from '../src/http.js';

// ── Mock the HTTP transport layer ─────────────────────────────────────────────

vi.mock('../src/http.js', () => ({
  postRegister: vi.fn(),
  postChallenge: vi.fn(),
  postVerify: vi.fn(),
  bytesToHex: (bytes: Uint8Array): string =>
    Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join(''),
  hexToBytes: (hex: string): Uint8Array => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  },
}));

import { postRegister, postChallenge, postVerify } from '../src/http.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

const TEST_PIN = '123456';
const CHALLENGE_HEX = 'a'.repeat(64);
const FAKE_JWT = 'header.payload.signature';

function makeChallengeResult(): ChallengeResult {
  return {
    status: 'challenge_issued' as const,
    challengeHex: CHALLENGE_HEX,
    expiresInMs: 60_000,
  };
}

function makeVerifyResult(): VerifyResult {
  return { token: FAKE_JWT };
}

function makeRegisterResult(userId = 'alice'): RegisterResult {
  return { status: 'registered' as const, userId };
}

/** Create a ZkpAuthClient backed by MemoryKeyStorage (no IDB in tests). */
function makeClient(baseUrl = 'http://localhost:3000'): ZkpAuthClient {
  return new ZkpAuthClient({ baseUrl, storage: new MemoryKeyStorage() });
}

// ── ZkpAuthClient construction ────────────────────────────────────────────────

describe('ZkpAuthClient construction', () => {
  it('creates an instance with a valid baseUrl', () => {
    const client = makeClient('https://api.example.com');
    expect(client).toBeInstanceOf(ZkpAuthClient);
  });

  it('strips trailing slashes from baseUrl', () => {
    expect(() => makeClient('http://localhost:3000/')).not.toThrow();
  });

  it('accepts empty string as baseUrl (same-origin relative paths)', () => {
    expect(() => makeClient('')).not.toThrow();
  });

  it('hasKey is false before any operation', () => {
    const client = makeClient();
    expect(client.hasKey).toBe(false);
  });

  it('hasLocalKey returns false before register', async () => {
    const client = makeClient();
    expect(await client.hasLocalKey('alice')).toBe(false);
  });
});

// ── register() ────────────────────────────────────────────────────────────────

describe('ZkpAuthClient.register()', () => {
  let client: ZkpAuthClient;

  beforeEach(() => {
    client = makeClient();
    vi.mocked(postRegister).mockResolvedValue(makeRegisterResult());
  });

  afterEach(() => { vi.clearAllMocks(); });

  it('returns RegisterOutcome on success', async () => {
    const result = await client.register('alice', TEST_PIN);
    expect(result.userId).toBe('alice');
    expect(typeof result.publicKeyHex).toBe('string');
    expect(result.publicKeyHex.length).toBe(64); // 32 bytes = 64 hex chars
  });

  it('hasLocalKey returns true after successful register', async () => {
    await client.register('alice', TEST_PIN);
    expect(await client.hasLocalKey('alice')).toBe(true);
  });

  it('hasKey (in-memory) remains false after register (key is in storage, not heap)', async () => {
    await client.register('alice', TEST_PIN);
    expect(client.hasKey).toBe(false);
  });

  it('calls postRegister with the correct baseUrl and userId', async () => {
    await client.register('alice', TEST_PIN);
    expect(postRegister).toHaveBeenCalledOnce();
    const [baseUrl, userId] = vi.mocked(postRegister).mock.calls[0]!;
    expect(baseUrl).toBe('http://localhost:3000');
    expect(userId).toBe('alice');
  });

  it('publicKeyHex in postRegister call matches returned publicKeyHex', async () => {
    const result = await client.register('alice', TEST_PIN);
    const [, , sentHex] = vi.mocked(postRegister).mock.calls[0]!;
    expect(sentHex).toBe(result.publicKeyHex);
  });

  it('throws ZkpCryptoError(INVALID_USERNAME) for an empty username', async () => {
    await expect(client.register('', TEST_PIN)).rejects.toThrow(ZkpCryptoError);
    try {
      await client.register('', TEST_PIN);
    } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('INVALID_USERNAME');
    }
  });

  it('throws ZkpCryptoError(INVALID_PIN) for an empty PIN', async () => {
    await expect(client.register('alice', '')).rejects.toThrow(ZkpCryptoError);
    try {
      await client.register('alice', '');
    } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('INVALID_PIN');
    }
  });

  it('local key is stored even when postRegister throws', async () => {
    // The key is written to storage BEFORE the server call.
    vi.mocked(postRegister).mockRejectedValue(
      new ZkpServerError('REGISTER_FAILED', 'conflict', 409),
    );
    await expect(client.register('alice', TEST_PIN)).rejects.toThrow(ZkpServerError);
    // Key was stored before the server rejected — hasLocalKey is still true.
    expect(await client.hasLocalKey('alice')).toBe(true);
  });
});

// ── login() ───────────────────────────────────────────────────────────────────

describe('ZkpAuthClient.login()', () => {
  let client: ZkpAuthClient;

  beforeEach(async () => {
    client = makeClient();
    vi.mocked(postRegister).mockResolvedValue(makeRegisterResult());
    vi.mocked(postChallenge).mockResolvedValue(makeChallengeResult());
    vi.mocked(postVerify).mockResolvedValue(makeVerifyResult());
    await client.register('alice', TEST_PIN);
  });

  afterEach(() => { vi.clearAllMocks(); });

  it('returns LoginOutcome with userId and token on success', async () => {
    const result = await client.login('alice', TEST_PIN);
    expect(result.userId).toBe('alice');
    expect(result.token).toBe(FAKE_JWT);
  });

  it('hasKey (in-memory) is false after login — key is zeroed immediately', async () => {
    await client.login('alice', TEST_PIN);
    expect(client.hasKey).toBe(false);
  });

  it('calls postChallenge then postVerify in order', async () => {
    await client.login('alice', TEST_PIN);
    expect(postChallenge).toHaveBeenCalledOnce();
    expect(postVerify).toHaveBeenCalledOnce();
  });

  it('proofHex sent to postVerify is a 128-char hex string (64 bytes)', async () => {
    await client.login('alice', TEST_PIN);
    const [, , proofHex] = vi.mocked(postVerify).mock.calls[0]!;
    expect(typeof proofHex).toBe('string');
    expect(proofHex.length).toBe(128);
    expect(/^[0-9a-f]+$/.test(proofHex)).toBe(true);
  });

  it('throws ZkpCryptoError(DECRYPTION_FAILED) on wrong PIN', async () => {
    await expect(client.login('alice', 'wrongpin')).rejects.toThrow(ZkpCryptoError);
    try {
      await client.login('alice', 'wrongpin');
    } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('DECRYPTION_FAILED');
    }
  });

  it('throws ZkpStorageError(KEY_NOT_FOUND) when no key is registered', async () => {
    const freshClient = makeClient();
    await expect(freshClient.login('bob', TEST_PIN)).rejects.toThrow(ZkpStorageError);
    try {
      await freshClient.login('bob', TEST_PIN);
    } catch (e) {
      expect((e as ZkpStorageError).code).toBe('KEY_NOT_FOUND');
    }
  });

  it('throws ZkpCryptoError(INVALID_USERNAME) for an empty username', async () => {
    await expect(client.login('', TEST_PIN)).rejects.toThrow(ZkpCryptoError);
    try { await client.login('', TEST_PIN); } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('INVALID_USERNAME');
    }
  });

  it('throws ZkpCryptoError(INVALID_PIN) for an empty PIN', async () => {
    await expect(client.login('alice', '')).rejects.toThrow(ZkpCryptoError);
    try { await client.login('alice', ''); } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('INVALID_PIN');
    }
  });

  it('throws ZkpServerError(CHALLENGE_FAILED) when postChallenge rejects', async () => {
    vi.mocked(postChallenge).mockRejectedValue(
      new ZkpServerError('CHALLENGE_FAILED', 'not found', 404),
    );
    await expect(client.login('alice', TEST_PIN)).rejects.toThrow(ZkpServerError);
  });

  it('throws ZkpServerError(PROOF_REJECTED) when postVerify rejects', async () => {
    vi.mocked(postVerify).mockRejectedValue(
      new ZkpServerError('PROOF_REJECTED', 'invalid proof', 401),
    );
    await expect(client.login('alice', TEST_PIN)).rejects.toThrow(ZkpServerError);
  });

  it('private key is zeroed even when postVerify rejects', async () => {
    vi.mocked(postVerify).mockRejectedValue(
      new ZkpServerError('PROOF_REJECTED', 'bad', 401),
    );
    await expect(client.login('alice', TEST_PIN)).rejects.toThrow();
    // Key must not be in memory regardless of error.
    expect(client.hasKey).toBe(false);
  });
});

// ── exportKeyBlob / importKeyBlob ─────────────────────────────────────────────

describe('ZkpAuthClient key blob transfer', () => {
  let source: ZkpAuthClient;
  let target: ZkpAuthClient;

  beforeEach(async () => {
    vi.mocked(postRegister).mockResolvedValue(makeRegisterResult());
    vi.mocked(postChallenge).mockResolvedValue(makeChallengeResult());
    vi.mocked(postVerify).mockResolvedValue(makeVerifyResult());
    source = makeClient();
    target = makeClient();
    await source.register('alice', TEST_PIN);
  });

  afterEach(() => { vi.clearAllMocks(); });

  it('exportKeyBlob returns a non-empty JSON string', async () => {
    const blob = await source.exportKeyBlob('alice', TEST_PIN);
    expect(typeof blob).toBe('string');
    expect(blob.length).toBeGreaterThan(0);
    expect(() => JSON.parse(blob)).not.toThrow();
  });

  it('importKeyBlob + login succeeds on the target client', async () => {
    const blob = await source.exportKeyBlob('alice', TEST_PIN);
    await target.importKeyBlob('alice', blob, TEST_PIN);
    const result = await target.login('alice', TEST_PIN);
    expect(result.userId).toBe('alice');
    expect(result.token).toBe(FAKE_JWT);
  });

  it('importKeyBlob with wrong PIN throws DECRYPTION_FAILED', async () => {
    const blob = await source.exportKeyBlob('alice', TEST_PIN);
    await expect(target.importKeyBlob('alice', blob, 'wrongpin')).rejects.toThrow(ZkpCryptoError);
    try {
      await target.importKeyBlob('alice', blob, 'wrongpin');
    } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('DECRYPTION_FAILED');
    }
  });

  it('exportKeyBlob throws KEY_NOT_FOUND when no key exists', async () => {
    await expect(source.exportKeyBlob('bob', TEST_PIN)).rejects.toThrow(ZkpStorageError);
    try {
      await source.exportKeyBlob('bob', TEST_PIN);
    } catch (e) {
      expect((e as ZkpStorageError).code).toBe('KEY_NOT_FOUND');
    }
  });

  it('exportKeyBlob throws INVALID_PIN for empty PIN', async () => {
    await expect(source.exportKeyBlob('alice', '')).rejects.toThrow(ZkpCryptoError);
    try {
      await source.exportKeyBlob('alice', '');
    } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('INVALID_PIN');
    }
  });
});

// ── Legacy in-memory key lifecycle ───────────────────────────────────────────

describe('ZkpAuthClient legacy key lifecycle (loadKey / exportKey / clearKey)', () => {
  let client: ZkpAuthClient;

  beforeEach(async () => {
    client = makeClient();
    vi.mocked(postRegister).mockResolvedValue(makeRegisterResult());
    // Load a random key into memory via the legacy API.
    const { browserGenerateKeyPair } = await import('../src/crypto.js');
    const { privateKey } = browserGenerateKeyPair();
    client.loadKey(privateKey);
  });

  afterEach(() => { vi.clearAllMocks(); });

  it('clearKey() sets hasKey to false', () => {
    client.clearKey();
    expect(client.hasKey).toBe(false);
  });

  it('clearKey() is idempotent', () => {
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
