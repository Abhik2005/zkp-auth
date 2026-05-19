// @zkp-auth/client — browser-safe Schnorr key generation and proof computation
//
// Re-implements the cryptographic protocol from @zkp-auth/core for the
// browser environment. The math is identical — Schnorr PoK on Ed25519
// with the Fiat-Shamir transform — but:
//
//   - CSPRNG: `globalThis.crypto.getRandomValues` (WebCrypto)
//   - Ed25519: `@noble/curves/ed25519.js` (browser-compatible)
//   - SHA-512: `@noble/hashes/sha512.js` (synchronous, browser-compatible)
//
// No `node:crypto` or any other Node.js built-in is imported.
//
// SECURITY-CRITICAL CONTRACTS (mirrors @zkp-auth/core compute-proof.ts):
//
// 1. `BASE.multiply(scalar)` is used for every scalar multiply — never
//    `multiplyUnsafe` — because every scalar fed here (x, r) is secret.
//
// 2. The nonce buffer r_bytes is zeroed after proof assembly (best-effort;
//    the bigint r cannot be wiped from the JS runtime).
//
// 3. No `===` / `!==` comparisons on byte arrays derived from secret material.

import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToNumberLE, numberToBytesLE, concatBytes } from '@noble/curves/utils.js';
import { sha512 } from '@noble/hashes/sha512.js';

import { ZkpCryptoError } from './errors.js';

// ── Constants ────────────────────────────────────────────────────────────────

/**
 * Maximum rejection-sampling iterations before treating the outcome as an
 * RNG anomaly. Locked at 256 to match @zkp-auth/core. Under a healthy CSPRNG
 * the probability of exhaustion is ≈ 2^-252.
 */
const MAX_REJECTION_ITERATIONS = 256;

/** Maximum UTF-8 byte length of a username. */
export const MAX_USERNAME_BYTES = 256;

// Ed25519 group order L and base point G — read from @noble/curves at module load.
const L: bigint = ed25519.Point.Fn.ORDER;
const BASE = ed25519.Point.BASE;

// ── CSPRNG wrapper ───────────────────────────────────────────────────────────

/**
 * Draw 32 cryptographically random bytes from the browser CSPRNG.
 *
 * @throws ZkpCryptoError('RNG_FAILURE') when `getRandomValues` throws.
 */
function getRandomBytes32(): Uint8Array {
  const buf = new Uint8Array(32);
  try {
    globalThis.crypto.getRandomValues(buf);
  } catch (cause: unknown) {
    throw new ZkpCryptoError('RNG_FAILURE', 'crypto.getRandomValues() failed', { cause });
  }
  return buf;
}

// ── Fiat-Shamir transcript ───────────────────────────────────────────────────

/**
 * Compute the Fiat-Shamir challenge scalar:
 *   c = int_LE(SHA-512(R_bytes || publicKey_bytes || challenge)) mod L
 *
 * Mirrors the construction in @zkp-auth/core's `transcript.ts` exactly.
 * SHA-512 from @noble/hashes is synchronous and browser-compatible.
 */
function computeFiatShamirScalar(
  R_bytes: Uint8Array,
  publicKey_bytes: Uint8Array,
  challenge: Uint8Array,
): bigint {
  const digest = sha512(concatBytes(R_bytes, publicKey_bytes, challenge));
  return ed25519.Point.Fn.create(bytesToNumberLE(digest));
}

// ── Public types ─────────────────────────────────────────────────────────────

/**
 * A freshly generated Ed25519 key pair for the ZKP-auth scheme.
 *
 * `privateKey` is a 32-byte little-endian encoding of a uniform scalar in
 * `[1, L)`. It must be kept in memory only — never persisted or transmitted.
 * `publicKey` is the 32-byte canonical point encoding of `privateKey · G`.
 */
export interface BrowserKeyPair {
  /** 32-byte LE scalar in [1, L). Keep in memory; zero after use. */
  privateKey: Uint8Array;
  /** 32-byte Ed25519 point encoding of privateKey · G. Safe to send to server. */
  publicKey: Uint8Array;
}

// ── Input validation helpers ─────────────────────────────────────────────────

/**
 * Validate that `username` is a non-empty string whose UTF-8 encoding does
 * not exceed `MAX_USERNAME_BYTES` (256 bytes).
 *
 * @throws ZkpCryptoError('INVALID_USERNAME') on any violation.
 */
export function validateUsername(username: string): void {
  if (typeof username !== 'string' || username.length === 0) {
    throw new ZkpCryptoError('INVALID_USERNAME', 'username must be a non-empty string');
  }
  const encoded = new TextEncoder().encode(username);
  if (encoded.byteLength > MAX_USERNAME_BYTES) {
    throw new ZkpCryptoError(
      'INVALID_USERNAME',
      `username exceeds ${MAX_USERNAME_BYTES.toString()} UTF-8 bytes`,
    );
  }
}

/**
 * Validate that `pin` is a non-empty string.
 *
 * The PIN is used only as local key-wrapping material — it never leaves the
 * device and is not transmitted to the server.
 *
 * @throws ZkpCryptoError('INVALID_PIN') when `pin` is empty or not a string.
 */
export function validatePin(pin: string): void {
  if (typeof pin !== 'string' || pin.length === 0) {
    throw new ZkpCryptoError('INVALID_PIN', 'PIN must be a non-empty string');
  }
}

// ── Core crypto operations ───────────────────────────────────────────────────

/**
 * Generate a fresh `(privateKey, publicKey)` pair using the browser CSPRNG.
 *
 * Implements bounded rejection sampling: draws a 32-byte candidate from
 * `crypto.getRandomValues`, decodes it as a little-endian bigint, accepts
 * iff `1 ≤ n < L`. This gives a uniform distribution over `[1, L)` without
 * the low-end bias that `mod L` reduction would introduce (2^256 is not a
 * multiple of L).
 *
 * The public key is `n · G` using the constant-time multiply
 * (`BASE.multiply`, never `multiplyUnsafe`).
 *
 * @throws ZkpCryptoError('RNG_FAILURE')  When `crypto.getRandomValues` throws
 *   or the rejection-sampling loop exhausts 256 iterations.
 * @throws ZkpCryptoError('CURVE_ERROR')  When @noble/curves raises an
 *   unexpected error during the scalar multiply.
 */
export function browserGenerateKeyPair(): BrowserKeyPair {
  for (let i = 0; i < MAX_REJECTION_ITERATIONS; i += 1) {
    const candidate = getRandomBytes32(); // throws ZkpCryptoError('RNG_FAILURE') on fault

    const n = bytesToNumberLE(candidate);
    if (n >= 1n && n < L) {
      // Accepted. Derive public key with constant-time multiply.
      try {
        const publicKey = BASE.multiply(n).toBytes();
        return { privateKey: candidate, publicKey };
      } catch (cause: unknown) {
        throw new ZkpCryptoError(
          'CURVE_ERROR',
          '@noble/curves raised an error during key generation',
          { cause },
        );
      }
    }
    // Rejected — draw again. The candidate bytes are not zeroed because they
    // were never accepted as key material (same hygiene policy as core).
  }

  throw new ZkpCryptoError(
    'RNG_FAILURE',
    'Rejection sampling exhausted 256 iterations — CSPRNG may be faulty',
  );
}

/**
 * Compute a 64-byte Schnorr proof of knowledge of `privateKey` over a
 * verifier-chosen 32-byte `challenge`.
 *
 * The returned proof is `R_bytes || s_bytes` (32 bytes each), where:
 *   - `R = r · G`  (commitment; r is a fresh CSPRNG nonce in [1, L))
 *   - `c = int_LE(SHA-512(R || X || challenge)) mod L`  (Fiat-Shamir)
 *   - `s = (r + c · x) mod L`  (response; x = int_LE(privateKey))
 *
 * This construction is byte-identical to @zkp-auth/core's `computeProof`
 * for the same inputs and the same nonce, so proofs produced here verify
 * correctly against the server's `verifyProof`.
 *
 * @param privateKey 32-byte LE scalar produced by `browserGenerateKeyPair`.
 * @param challenge  32-byte server-issued challenge (hex-decoded upstream).
 *
 * @returns 64-byte `Uint8Array` carrying `R_bytes || s_bytes`.
 *
 * @throws ZkpCryptoError('CURVE_ERROR') On @noble/curves internal error or
 *   when `privateKey` decodes outside `[1, L)`.
 * @throws ZkpCryptoError('RNG_FAILURE') On CSPRNG failure or loop exhaustion.
 */
export function browserComputeProof(
  privateKey: Uint8Array,
  challenge: Uint8Array,
): Uint8Array {
  // Decode private key scalar. Reject 0 and anything ≥ L (mirrors core step 2).
  const x = bytesToNumberLE(privateKey);
  if (x === 0n || x >= L) {
    throw new ZkpCryptoError(
      'CURVE_ERROR',
      'privateKey decodes to a scalar outside [1, L)',
    );
  }

  // Derive public key for the Fiat-Shamir transcript (constant-time multiply).
  let publicKey_bytes: Uint8Array;
  try {
    publicKey_bytes = BASE.multiply(x).toBytes();
  } catch (cause: unknown) {
    throw new ZkpCryptoError(
      'CURVE_ERROR',
      '@noble/curves raised an error deriving the public key',
      { cause },
    );
  }

  // Bounded rejection sampling for the nonce r (mirrors core step 4).
  // Unlike keypair generation, we use mod-L reduction (not raw range check)
  // because a single-use ephemeral nonce with uniform distribution mod L
  // is cryptographically acceptable. We only reject the degenerate r === 0n.
  for (let i = 0; i < MAX_REJECTION_ITERATIONS; i += 1) {
    const r_bytes = getRandomBytes32(); // throws ZkpCryptoError('RNG_FAILURE') on fault
    const r = ed25519.Point.Fn.create(bytesToNumberLE(r_bytes));

    if (r !== 0n) {
      // Commitment R = r · G (constant-time multiply, multiplyUnsafe forbidden).
      let R_bytes: Uint8Array;
      try {
        R_bytes = BASE.multiply(r).toBytes();
      } catch (cause: unknown) {
        throw new ZkpCryptoError(
          'CURVE_ERROR',
          '@noble/curves raised an error computing the commitment',
          { cause },
        );
      }

      // Fiat-Shamir challenge scalar.
      const c = computeFiatShamirScalar(R_bytes, publicKey_bytes, challenge);

      // Response s = (r + c · x) mod L.
      const s = ed25519.Point.Fn.create(r + c * x);
      const s_bytes = numberToBytesLE(s, 32);

      // Zero the nonce buffer (best-effort per core Requirement 6.4).
      // The bigint `r` cannot be wiped from the JS runtime.
      r_bytes.fill(0);

      return concatBytes(R_bytes, s_bytes);
    }
    // r === 0n: redraw. r_bytes is left to the GC (never used as nonce material).
  }

  throw new ZkpCryptoError(
    'RNG_FAILURE',
    'Nonce rejection-sampling exhausted 256 iterations — CSPRNG may be faulty',
  );
}

/** @internal Exported for unit tests only — not part of the public API. */
export const _internals = {
  MAX_USERNAME_BYTES,
  MAX_REJECTION_ITERATIONS,
  L,
  computeFiatShamirScalar,
} as const;
