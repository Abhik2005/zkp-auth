// tests/crypto.test.ts — unit tests for browser-safe Schnorr operations
//
// Tier: Unit
// Covers: browserGenerateKeyPair, browserComputeProof,
//         validateUsername, encodePassword, Fiat-Shamir scalar
// Environment: jsdom (provides globalThis.crypto via @vitest/browser or jsdom)

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  browserGenerateKeyPair,
  browserDeriveKeyPair,
  browserComputeProof,
  validateUsername,
  encodePassword,
  MAX_USERNAME_BYTES,
  MAX_PASSWORD_BYTES,
  _internals,
} from '../src/crypto.js';
import { ZkpCryptoError } from '../src/errors.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToNumberLE } from '@noble/curves/utils.js';

const L = _internals.L;

// ── validateUsername ──────────────────────────────────────────────────────────

describe('validateUsername', () => {
  it('accepts a normal username', () => {
    expect(() => validateUsername('alice')).not.toThrow();
  });

  it('rejects an empty string', () => {
    expect(() => validateUsername('')).toThrow(ZkpCryptoError);
    try { validateUsername(''); } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('INVALID_USERNAME');
    }
  });

  it('rejects a non-string value', () => {
    expect(() => validateUsername(42 as unknown as string)).toThrow(ZkpCryptoError);
  });

  it('accepts a username exactly at the byte limit', () => {
    const atLimit = 'a'.repeat(MAX_USERNAME_BYTES);
    expect(() => validateUsername(atLimit)).not.toThrow();
  });

  it('rejects a username one byte over the limit', () => {
    const overLimit = 'a'.repeat(MAX_USERNAME_BYTES + 1);
    expect(() => validateUsername(overLimit)).toThrow(ZkpCryptoError);
    try { validateUsername(overLimit); } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('INVALID_USERNAME');
    }
  });
});

// ── encodePassword ────────────────────────────────────────────────────────────

describe('encodePassword', () => {
  it('returns a Uint8Array for a normal password', () => {
    const bytes = encodePassword('hunter2');
    // Use ArrayBuffer.isView to avoid jsdom cross-realm instanceof mismatch.
    expect(ArrayBuffer.isView(bytes)).toBe(true);
    expect(bytes.byteLength).toBe(7);
  });

  it('accepts an empty password', () => {
    const bytes = encodePassword('');
    expect(bytes.byteLength).toBe(0);
  });

  it('accepts a password exactly at the byte limit', () => {
    const atLimit = 'a'.repeat(MAX_PASSWORD_BYTES);
    expect(() => encodePassword(atLimit)).not.toThrow();
  });

  it('rejects a password one byte over the limit', () => {
    const overLimit = 'a'.repeat(MAX_PASSWORD_BYTES + 1);
    expect(() => encodePassword(overLimit)).toThrow(ZkpCryptoError);
    try { encodePassword(overLimit); } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('INVALID_PASSWORD');
    }
  });
});

// ── browserGenerateKeyPair ────────────────────────────────────────────────────

describe('browserGenerateKeyPair', () => {
  it('returns privateKey and publicKey as Uint8Array(32)', () => {
    const { privateKey, publicKey } = browserGenerateKeyPair();
    expect(privateKey).toBeInstanceOf(Uint8Array);
    expect(publicKey).toBeInstanceOf(Uint8Array);
    expect(privateKey.byteLength).toBe(32);
    expect(publicKey.byteLength).toBe(32);
  });

  it('privateKey scalar is in [1, L)', () => {
    const { privateKey } = browserGenerateKeyPair();
    const n = bytesToNumberLE(privateKey);
    expect(n >= 1n).toBe(true);
    expect(n < L).toBe(true);
  });

  it('publicKey is a valid Ed25519 point (decodes without error)', () => {
    const { publicKey } = browserGenerateKeyPair();
    expect(() => ed25519.Point.fromBytes(publicKey)).not.toThrow();
  });

  it('publicKey is not the identity point (0 · G)', () => {
    const { publicKey } = browserGenerateKeyPair();
    const point = ed25519.Point.fromBytes(publicKey);
    expect(point.equals(ed25519.Point.ZERO)).toBe(false);
  });

  it('two successive calls produce different keys', () => {
    const kp1 = browserGenerateKeyPair();
    const kp2 = browserGenerateKeyPair();
    // The probability of collision is ≈ 2^-252 — treat equal as a test bug.
    expect(Buffer.from(kp1.privateKey).equals(Buffer.from(kp2.privateKey))).toBe(false);
  });

  it('publicKey equals privateKey_scalar · G', () => {
    const { privateKey, publicKey } = browserGenerateKeyPair();
    const scalar = bytesToNumberLE(privateKey);
    const expected = ed25519.Point.BASE.multiply(scalar).toBytes();
    expect(Buffer.from(publicKey).equals(Buffer.from(expected))).toBe(true);
  });

  it('throws ZkpCryptoError(RNG_FAILURE) when getRandomValues is broken', () => {
    // Capture the spy reference so mockRestore() targets the right spy.
    const spy = vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(() => {
      throw new DOMException('mocked CSPRNG failure', 'SecurityError');
    });
    try {
      expect(() => browserGenerateKeyPair()).toThrow(ZkpCryptoError);
      try { browserGenerateKeyPair(); } catch (e) {
        expect((e as ZkpCryptoError).code).toBe('RNG_FAILURE');
      }
    } finally {
      spy.mockRestore();
    }
  });
});

// ── browserComputeProof ───────────────────────────────────────────────────────

describe('browserComputeProof', () => {
  let privateKey: Uint8Array;
  let publicKey: Uint8Array;
  let challenge: Uint8Array;
  const password = new TextEncoder().encode('testpassword');

  beforeEach(() => {
    const kp = browserGenerateKeyPair();
    privateKey = kp.privateKey;
    publicKey = kp.publicKey;
    challenge = globalThis.crypto.getRandomValues(new Uint8Array(32));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns a 64-byte Uint8Array', () => {
    const proof = browserComputeProof(privateKey, password, challenge);
    expect(proof).toBeInstanceOf(Uint8Array);
    expect(proof.byteLength).toBe(64);
  });

  it('R_bytes (first 32) decodes as a valid Ed25519 point', () => {
    const proof = browserComputeProof(privateKey, password, challenge);
    const R_bytes = proof.slice(0, 32);
    expect(() => ed25519.Point.fromBytes(R_bytes)).not.toThrow();
  });

  it('s_bytes (last 32) is a scalar in [0, L)', () => {
    const proof = browserComputeProof(privateKey, password, challenge);
    const s_bytes = proof.slice(32);
    const s = bytesToNumberLE(s_bytes);
    expect(s >= 0n).toBe(true);
    expect(s < L).toBe(true);
  });

  it('proof verifies under Schnorr equation: s·G == R + c·publicKey', () => {
    const proof = browserComputeProof(privateKey, password, challenge);
    const R_bytes = proof.slice(0, 32);
    const s_bytes = proof.slice(32);

    const R = ed25519.Point.fromBytes(R_bytes);
    const X = ed25519.Point.fromBytes(publicKey);
    const s = bytesToNumberLE(s_bytes);
    const c = _internals.computeFiatShamirScalar(R_bytes, publicKey, challenge);

    // s · G == R + c · X
    const lhs = ed25519.Point.BASE.multiply(s);
    const rhs = R.add(X.multiply(c));
    expect(lhs.equals(rhs)).toBe(true);
  });

  it('password is not mixed into the proof (two passwords → same proof for same nonce)', () => {
    // We cannot fix the nonce in production, but we can verify that
    // two proofs with different passwords are both valid under the equation.
    // A stricter byte-equality test requires the __forTesting__ hook from core
    // and is deferred to integration tests.
    const proof1 = browserComputeProof(privateKey, new TextEncoder().encode('pass1'), challenge);
    const proof2 = browserComputeProof(privateKey, new TextEncoder().encode('pass2'), challenge);

    // Both must be 64 bytes and verify correctly (even if the nonce differs).
    expect(proof1.byteLength).toBe(64);
    expect(proof2.byteLength).toBe(64);

    for (const proof of [proof1, proof2]) {
      const R = ed25519.Point.fromBytes(proof.slice(0, 32));
      const s = bytesToNumberLE(proof.slice(32));
      const c = _internals.computeFiatShamirScalar(proof.slice(0, 32), publicKey, challenge);
      expect(ed25519.Point.BASE.multiply(s).equals(R.add(ed25519.Point.fromBytes(publicKey).multiply(c)))).toBe(true);
    }
  });

  it('throws ZkpCryptoError(CURVE_ERROR) when privateKey is zero', () => {
    const zeroKey = new Uint8Array(32);
    expect(() => browserComputeProof(zeroKey, password, challenge)).toThrow(ZkpCryptoError);
    try { browserComputeProof(zeroKey, password, challenge); } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('CURVE_ERROR');
    }
  });

  it('throws ZkpCryptoError(CURVE_ERROR) when privateKey scalar >= L', () => {
    // Encode L itself into 32 bytes LE — it is >= L, must be rejected.
    const lBytes = new Uint8Array(32);
    let tmp = L;
    for (let i = 0; i < 32; i++) {
      lBytes[i] = Number(tmp & 0xffn);
      tmp >>= 8n;
    }
    expect(() => browserComputeProof(lBytes, password, challenge)).toThrow(ZkpCryptoError);
    try { browserComputeProof(lBytes, password, challenge); } catch (e) {
      expect((e as ZkpCryptoError).code).toBe('CURVE_ERROR');
    }
  });

  it('two proofs over the same inputs differ (fresh nonce each time)', () => {
    const proof1 = browserComputeProof(privateKey, password, challenge);
    const proof2 = browserComputeProof(privateKey, password, challenge);
    // R_bytes should differ (different random nonces).
    expect(Buffer.from(proof1.slice(0, 32)).equals(Buffer.from(proof2.slice(0, 32)))).toBe(false);
  });
});

// ── Fiat-Shamir scalar ────────────────────────────────────────────────────────

describe('computeFiatShamirScalar (internal)', () => {
  it('returns a bigint in [0, L)', () => {
    const R = new Uint8Array(32).fill(1);
    const pub = new Uint8Array(32).fill(2);
    const ch = new Uint8Array(32).fill(3);
    const c = _internals.computeFiatShamirScalar(R, pub, ch);
    expect(typeof c).toBe('bigint');
    expect(c >= 0n).toBe(true);
    expect(c < L).toBe(true);
  });

  it('is deterministic for the same inputs', () => {
    const R = new Uint8Array(32).fill(7);
    const pub = new Uint8Array(32).fill(8);
    const ch = new Uint8Array(32).fill(9);
    expect(_internals.computeFiatShamirScalar(R, pub, ch)).toBe(
      _internals.computeFiatShamirScalar(R, pub, ch),
    );
  });

  it('differs when the challenge changes', () => {
    const R = new Uint8Array(32).fill(1);
    const pub = new Uint8Array(32).fill(2);
    const ch1 = new Uint8Array(32).fill(3);
    const ch2 = new Uint8Array(32).fill(4);
    expect(_internals.computeFiatShamirScalar(R, pub, ch1)).not.toBe(
      _internals.computeFiatShamirScalar(R, pub, ch2),
    );
  });
});
/** Low iteration count for test speed. Production uses 600_000. */
const TEST_PBKDF2_ITERS = 1_000;

describe('browserDeriveKeyPair', () => {
  it('returns privateKey and publicKey as Uint8Array(32)', async () => {
    const { privateKey, publicKey } = await browserDeriveKeyPair('alice', 'secret', TEST_PBKDF2_ITERS);
    expect(ArrayBuffer.isView(privateKey)).toBe(true);
    expect(ArrayBuffer.isView(publicKey)).toBe(true);
    expect(privateKey.byteLength).toBe(32);
    expect(publicKey.byteLength).toBe(32);
  });

  it('privateKey scalar is in [1, L)', async () => {
    const { privateKey } = await browserDeriveKeyPair('alice', 'secret', TEST_PBKDF2_ITERS);
    const n = bytesToNumberLE(privateKey);
    expect(n >= 1n).toBe(true);
    expect(n < L).toBe(true);
  });

  it('publicKey is a valid Ed25519 point', async () => {
    const { publicKey } = await browserDeriveKeyPair('alice', 'secret', TEST_PBKDF2_ITERS);
    expect(() => ed25519.Point.fromBytes(publicKey)).not.toThrow();
  });

  it('is deterministic — same credentials always produce the same keypair', async () => {
    const kp1 = await browserDeriveKeyPair('alice', 'secret', TEST_PBKDF2_ITERS);
    const kp2 = await browserDeriveKeyPair('alice', 'secret', TEST_PBKDF2_ITERS);
    expect(Buffer.from(kp1.privateKey).equals(Buffer.from(kp2.privateKey))).toBe(true);
    expect(Buffer.from(kp1.publicKey).equals(Buffer.from(kp2.publicKey))).toBe(true);
  });

  it('different passwords produce different keypairs', async () => {
    const kp1 = await browserDeriveKeyPair('alice', 'secret1', TEST_PBKDF2_ITERS);
    const kp2 = await browserDeriveKeyPair('alice', 'secret2', TEST_PBKDF2_ITERS);
    expect(Buffer.from(kp1.privateKey).equals(Buffer.from(kp2.privateKey))).toBe(false);
  });

  it('different usernames produce different keypairs (same password)', async () => {
    const kp1 = await browserDeriveKeyPair('alice', 'secret', TEST_PBKDF2_ITERS);
    const kp2 = await browserDeriveKeyPair('bob', 'secret', TEST_PBKDF2_ITERS);
    expect(Buffer.from(kp1.privateKey).equals(Buffer.from(kp2.privateKey))).toBe(false);
  });

  it('publicKey equals privateKey_scalar · G', async () => {
    const { privateKey, publicKey } = await browserDeriveKeyPair('alice', 'secret', TEST_PBKDF2_ITERS);
    const scalar = bytesToNumberLE(privateKey);
    const expected = ed25519.Point.BASE.multiply(scalar).toBytes();
    expect(Buffer.from(publicKey).equals(Buffer.from(expected))).toBe(true);
  });

  it('_internals.PBKDF2_ITERATIONS is a positive integer', () => {
    expect(typeof _internals.PBKDF2_ITERATIONS).toBe('number');
    expect(_internals.PBKDF2_ITERATIONS).toBeGreaterThan(0);
  });
});
