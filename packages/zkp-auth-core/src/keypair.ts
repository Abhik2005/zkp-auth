// @zkp-auth/core — `generateKeyPair` with bounded rejection sampling
//
// This module implements the sole key-generation entry point of
// `@zkp-auth/core`. It draws a 32-byte candidate from the CSPRNG
// chokepoint (`./rng.js`), accepts it iff its little-endian decoding is
// a scalar `n` with `1 <= n < L`, and emits the public key as the
// canonical encoding of `n · G` where `G = BASE` is the Ed25519
// generator. The acceptance test is implemented as bounded rejection
// sampling — never as modular reduction — so the emitted `privateKey`
// is uniform over `[1, L)` (Requirement 1.2), with no skew toward the
// low end of the scalar range that a `mod L` strategy would introduce
// because `2^256` is not a multiple of `L`.
//
// Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 11.2
// See design.md → "Components and Interfaces → keypair.ts" and
//     design.md → "Key design decisions → 2" (rejection-sampling bound).
//
// Implementation notes:
//
// - The bound `MAX_REJECTION_ITERATIONS = 256` is the value locked by
//   the design. Under a healthy CSPRNG the probability that a single
//   32-byte draw lies outside `[1, L)` is ≈ `1 - L / 2^256 ≈ 2^-252`,
//   so 256 successive rejections is statistically indistinguishable
//   from impossible — exhausting the loop is treated as an RNG anomaly
//   and surfaces as `RandomnessError` with stable code `'RNG_FAILURE'`,
//   matching the failure taxonomy of the CSPRNG wrapper itself
//   (Requirement 1.5).
//
// - We use the constant-time `BASE.multiply(n)` from `@noble/curves`,
//   never `multiplyUnsafe`. `multiplyUnsafe` skips the constant-time
//   ladder and would leak the secret scalar via timing — forbidden by
//   the project's audit rules and the design's "Key design decisions →
//   4". `multiply` is invoked exactly once, on the accepted candidate.
//
// - The accepted `candidate` is returned AS-IS as `privateKey`. We do
//   NOT clamp (Ed25519 EdDSA-style bit clamping) and do NOT hash. This
//   is what distinguishes our key shape from `ed25519.keygen()`'s
//   RFC-8032 seed → expanded scalar pipeline; see "External API
//   Surface §F" in design.md. Downstream `computeProof` consumes the
//   raw 32-byte little-endian scalar, so any transform here would
//   break the round-trip property (Requirement 4 / Property 6).
//
// - The lower bound `n >= 1n` rules out the all-zero key explicitly.
//   `n = 0` would yield `publicKey = encode(0 · G) = encode(O)` (the
//   identity / neutral element), which is the privacy-critical
//   degenerate case Requirement 11.4 calls out: a zero key would make
//   the proof trivially verify against any challenge, breaking the
//   soundness contract of the scheme.
//
// - There are no `===` / `!==` comparisons or `Buffer.equals` calls on
//   secret byte arrays in this file. The accept test is performed in
//   bigint domain (`n >= 1n && n < L`), which does not invoke any
//   byte-level equality on `candidate` and is not a path the audit
//   guard (task 13.1) needs to flag.

import { randomBytes32 } from './rng.js';
import { scalarFromBytesLE, L, BASE, pointToBytes } from './encoding.js';
import { RandomnessError } from './errors.js';

/**
 * Maximum number of rejection-sampling iterations before treating the
 * loop as an RNG anomaly. Locked at 256 by design.md "Key design
 * decisions → 2"; see the file-header comment above for the
 * statistical justification.
 */
const MAX_REJECTION_ITERATIONS = 256;

/**
 * Generates a fresh `(privateKey, publicKey)` pair for the ZKP-auth
 * scheme.
 *
 * The `privateKey` is a uniform 32-byte little-endian encoding of a
 * scalar `n ∈ [1, L)`, drawn via bounded rejection sampling against
 * the CSPRNG chokepoint `randomBytes32()`. The `publicKey` is the
 * canonical 32-byte encoding of `n · G`, where `G` is the Ed25519
 * base point.
 *
 * The two outputs are returned as fresh `Uint8Array` instances —
 * `privateKey` is the accepted CSPRNG draw itself (a copy detached
 * from Node's internal buffer pool, see `rng.ts`'s `Uint8Array.from`
 * step), and `publicKey` is produced by `@noble/curves`'s `toBytes()`
 * which allocates a fresh array. Callers may zero-fill the returned
 * `privateKey` after use without affecting any other observer
 * (Requirement 6.4 hygiene; not enforced by this function but
 * permitted by its allocation contract).
 *
 * Failure modes — both surface as `RandomnessError` with
 * `code === 'RNG_FAILURE'`, never as a partial or zero-padded result
 * (Requirement 1.5):
 *
 * - The underlying `randomBytes32()` throws (CSPRNG anomaly or short
 *   read). Any error — whether a `RandomnessError` already produced
 *   by `rng.ts`, or a raw `Error` injected by tests via `vi.mock` —
 *   is caught and, if not already a `RandomnessError`, re-wrapped as
 *   one. This mirrors the defense-in-depth pattern in `compute-proof.ts`.
 * - 256 successive draws all decode to scalars outside `[1, L)`. This
 *   is statistically impossible under a healthy CSPRNG (≈ `2^-252`
 *   per draw), so exhaustion is reported as an RNG failure rather
 *   than as a separate exhaustion-specific error class.
 *
 * @returns An object with `privateKey` (32 bytes, encoding a scalar
 *   in `[1, L)`) and `publicKey` (32 bytes, encoding `privateKey · G`).
 * @throws RandomnessError When the CSPRNG fails or rejection sampling
 *   exhausts its 256-iteration bound.
 */
export function generateKeyPair(): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
} {
  for (let i = 0; i < MAX_REJECTION_ITERATIONS; i += 1) {
    // `randomBytes32()` normally throws `RandomnessError` (CSPRNG fault
    // or short read) — already wrapped by `rng.ts`. In tests, `rng.ts`
    // is mocked via `vi.mock` and may throw a raw `Error`. We re-wrap
    // any non-`RandomnessError` here so the public-API contract
    // "throw only `InvalidInputError` or `RandomnessError`" holds at
    // this module boundary regardless of what the mock injects.
    let candidate: Uint8Array;
    try {
      candidate = randomBytes32();
    } catch (e) {
      if (e instanceof RandomnessError) throw e;
      throw new RandomnessError('CSPRNG failure', { cause: e });
    }

    // Raw little-endian decoding, no reduction. We REJECT out-of-range
    // candidates (per Requirement 1.2's "rejection sampling") rather
    // than reduce mod `L`, because reduction would skew the
    // distribution of accepted scalars toward the low end of `[0, L)`
    // — `2^256` is not an integer multiple of `L`.
    const n = scalarFromBytesLE(candidate);

    if (n >= 1n && n < L) {
      // Accepted. Derive the public key with the constant-time
      // scalar-multiply. `BASE.multiply` (not `multiplyUnsafe`) is
      // mandatory: this is the single point in this function where
      // the secret scalar `n` enters curve math, and any timing
      // variation here would directly leak `n`.
      const publicKey = pointToBytes(BASE.multiply(n));
      return { privateKey: candidate, publicKey };
    }
    // Rejected: continue the loop and draw a fresh candidate. The
    // rejected `candidate` is left to the GC; we do not zero-fill
    // here because the rejected bytes are not a secret — they were
    // never accepted as a private key and the CSPRNG-state info they
    // carry is no more sensitive than any other discarded RNG output.
  }

  // Loop exhausted without acceptance. Treated as an RNG anomaly per
  // design.md "Key design decisions → 2"; surfaces with the same
  // stable `.code` (`'RNG_FAILURE'`) as a CSPRNG throw or short read,
  // so callers can pattern-match on a single error code for all
  // randomness-related failures.
  throw new RandomnessError('rejection sampling exhausted');
}
