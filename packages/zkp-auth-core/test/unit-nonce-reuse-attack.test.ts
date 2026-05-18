// @zkp-auth/core — nonce-reuse adversarial documentation test
//
// Validates: Requirements 9.4
//
// This file documents — by demonstration on the implementation under
// test, via the test-only `__forTesting__.computeProofWithFixedNonce`
// hook — the classical "nonce-reuse" attack on Schnorr proofs. The
// attack is the reason Requirement 6 mandates a freshly drawn CSPRNG
// nonce on every `computeProof` call (Requirement 6.1) and a
// best-effort zero-fill of the nonce buffer afterwards
// (Requirement 6.4); production code NEVER reuses nonces, so this
// attack is structurally impossible against
// `compute-proof.ts`'s public `computeProof` entry point.
//
// THE ATTACK
//
// Suppose a prover, using the same secret scalar `x` (derived from
// `privateKey`), produces two Schnorr proofs that happen to share
// the same nonce `r` but were bound to two distinct verifier
// challenges `challenge1 ≠ challenge2`. The honest construction
// from `compute-proof.ts` would yield:
//
//   R    = r · G                                          (commitment, both proofs share)
//   c1   = int_LE(SHA-512(R || publicKey || challenge1)) mod L
//   c2   = int_LE(SHA-512(R || publicKey || challenge2)) mod L
//   s1   = (r + c1 · x) mod L
//   s2   = (r + c2 · x) mod L
//
// Subtracting the two response equations cancels `r`:
//
//   s1 - s2 ≡ (c1 - c2) · x   (mod L)
//
// Provided `c1 ≠ c2` (overwhelmingly likely by the random-oracle
// argument applied to SHA-512), the scalar `c1 - c2` is invertible
// mod L (L is prime — it is the order of the Ed25519 prime-order
// subgroup, the standard generator-order argument), and the secret
// scalar `x` falls out:
//
//   x ≡ (s1 - s2) · (c1 - c2)^(-1)   (mod L)
//
// Once `x` is recovered, the prover's `privateKey` is recovered
// (it IS the little-endian encoding of `x`, per Requirement 11.1's
// `x = int_LE(privateKey) mod L` and design's "raw scalar private
// keys, not RFC 8032 EdDSA seeds" decision: any in-range
// `privateKey` IS its own canonical scalar representative).
//
// The attack works against ANY implementation whose nonces are
// observable to coincide across two distinct challenges over the
// same key — bad CSPRNG, deterministic-with-leaked-state nonce
// derivation, hardware fault injection, etc. It is a textbook
// motivation for both Requirement 6.1 ("draw the nonce `r` from a
// CSPRNG on every invocation") and Requirement 6.4 (zero-fill the
// nonce buffer to limit residual heap exposure that could be
// observed by a heap-snapshot attacker).
//
// HOW THE LIBRARY DEFENDS
//
// `compute-proof.ts`'s public `computeProof` entry point draws a
// fresh 32-byte CSPRNG buffer per call (`randomBytes32()`),
// rejection-samples until the resulting scalar is non-zero in
// `[1, L)`, and zero-fills the buffer after the proof is assembled.
// There is NO public API surface in `@zkp-auth/core` that lets a
// caller pin the nonce — the `__forTesting__` namespace used by
// THIS test is explicitly excluded from `index.ts`'s public barrel
// (design "Components and Interfaces → `index.ts`") and the
// audit-marker comment in `compute-proof.ts` is grep-asserted in a
// future audit task to appear EXACTLY ONCE in `src/` (locking the
// "no production module imports the test hook" contract).
//
// Property 11 (test/property-11-nonce-freshness.test.ts) closes
// the live-RNG side of the same contract: 1000 successive
// `computeProof` calls under the real CSPRNG produce 1000 distinct
// `R_bytes` segments. Property 15
// (test/property-15-nonce-zero-fill.test.ts) closes the
// zero-fill side. This test closes the THIRD side — what would go
// wrong if those defenses were ever removed.
//
// WHY THIS IS A "DOCUMENTATION" TEST, NOT A CORRECTNESS PROPERTY
//
// The library does NOT claim, in production, to be safe against
// nonce reuse — it claims to PREVENT nonce reuse from arising in
// the first place. So this test is NOT asserting a property the
// production code actively satisfies; it is asserting a property of
// the underlying mathematics, exhibited by deliberately routing
// through the test-only hook with a pinned nonce. If the library's
// nonce-freshness guarantees ever regressed, this test is the one
// that explains to the next reviewer WHY the regression matters.
//
// PER-BYTE NUMERIC EQUALITY IS FINE IN THIS FILE
//
// This file is under `test/` and is NOT scanned by the audit guard
// (task 13.1, which scans `src/**/*.ts` only). The `===` /
// `Uint8Array`-element comparisons used in the precondition checks
// — and the `bigint` `===` used in the final recovery assertion —
// are all permitted here; none of them touches secret material at
// runtime in production code paths.
//
// See design.md → "Security Considerations → Nonce reuse",
//     design.md → "Components and Interfaces → compute-proof.ts"
//                 (the `__forTesting__` hook contract), and
//     requirements.md → "Requirement 6: Non-Functional — Fresh
//                       Nonces" and "Requirement 9.4".

import { describe, it, expect } from 'vitest';
import { hexToBytes } from '@noble/curves/utils.js';

import { __forTesting__ } from '../src/compute-proof.js';
import { computeFiatShamirScalar } from '../src/transcript.js';
import { L, BASE, pointToBytes, scalarFromBytesLE } from '../src/encoding.js';

// ---------------------------------------------------------------------
// Inline modular-arithmetic helpers
// ---------------------------------------------------------------------
//
// These helpers exist only in this test file. They are intentionally
// NOT taken from `encoding.ts` or any production module: the attack
// simulation must compute `(c1 - c2)^(-1) mod L` independently of the
// implementation under test, so a regression in the implementation
// cannot mask itself by also corrupting the verifier-side recovery
// math. Keeping them inline also documents — for the next reader of
// this file — exactly which mathematical primitives are needed to
// run the attack from raw bigint scalars.

/**
 * Square-and-multiply modular exponentiation `base^exp mod mod`.
 *
 * Used by `modInverse` to compute `a^(L - 2) mod L` per Fermat's
 * little theorem. Handles `exp >= 0`. The implementation pre-reduces
 * `base mod mod` defensively so callers may pass any `bigint`
 * (positive, negative, or already-reduced); the result is always in
 * `[0, mod)`.
 *
 * Not constant-time — but this is a test file, and `exp = L - 2`
 * is public, so timing leakage is not a concern here.
 */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  let result = 1n;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % mod;
    }
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

/**
 * Modular inverse `a^(-1) mod mod` via Fermat's little theorem.
 *
 * Valid only when `mod` is prime AND `a mod mod !== 0`. Both
 * conditions hold here:
 *
 *   - `L = ed25519.Point.Fn.ORDER` is the order of the Ed25519
 *     prime-order subgroup (a Sophie-Germain-style prime by curve
 *     construction; see RFC 7748 / RFC 8032).
 *   - `(c1 - c2) mod L !== 0n` is asserted as a precondition before
 *     this function is called (the second `it` block locks that
 *     precondition; the third `it` block additionally asserts it
 *     defensively immediately before computing the inverse).
 *
 * Pre-reduces `a mod mod` (and folds in `+ mod` to handle negative
 * inputs) before the exponentiation, so callers may pass `c1 - c2`
 * directly.
 */
function modInverse(a: bigint, mod: bigint): bigint {
  const aReduced = ((a % mod) + mod) % mod;
  return modPow(aReduced, mod - 2n, mod);
}

// ---------------------------------------------------------------------
// Attack inputs
// ---------------------------------------------------------------------
//
// All three byte strings are deterministic, hand-picked, and chosen
// to satisfy the implementation's input contracts:
//
//   - PRIVATE_KEY_HEX decodes to a scalar in `[1, L)` (verified
//     during selection; `L > 2^252` and the chosen value is just
//     under `2^252`, with the terminal byte `0x0e` keeping the
//     high bits below `L`'s leading byte). This is the SAME
//     `PRIVATE_KEY_HEX` used in `unit-fixed-vectors.test.ts`,
//     reused here so a reader can cross-reference the two files
//     without re-deriving the scalar by hand.
//   - NONCE_HEX decodes to a scalar in `[1, L)`, satisfying the
//     `__forTesting__.computeProofWithFixedNonce` hook's "well-formed
//     `r_bytes` of exactly 32 bytes whose `mod L` reduction is
//     non-zero" contract. Reused from the fixed-vectors test for
//     the same cross-reference reason.
//   - CHALLENGE_1_HEX and CHALLENGE_2_HEX are two DISTINCT 32-byte
//     verifier challenges. Any two distinct buffers work: SHA-512
//     applied to two different transcripts produces digests that
//     differ in the random-oracle model, and reducing each modulo
//     L preserves that distinctness with overwhelming probability
//     (the only collision modulus L mod 2^512 is on a measure-zero
//     subset of digests). The second `it` block defensively asserts
//     `c1 !== c2` before the recovery math runs.

/**
 * 32-byte little-endian encoding of the prover's `privateKey`.
 * Decodes to a scalar in `[1, L)`. Reused from
 * `unit-fixed-vectors.test.ts`.
 */
const PRIVATE_KEY_HEX =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd0e';

/**
 * 32-byte fixed nonce supplied to the `__forTesting__` hook. The
 * SAME `r_bytes` is used for both `proof1` and `proof2`, which is
 * the precondition that makes the nonce-reuse attack possible.
 * Decodes to a scalar in `[1, L)`. Reused from
 * `unit-fixed-vectors.test.ts`.
 */
const NONCE_HEX =
  'c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec00f';

/** First verifier challenge. Distinct from `CHALLENGE_2_HEX`. */
const CHALLENGE_1_HEX =
  'feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfac0';

/** Second verifier challenge. Distinct from `CHALLENGE_1_HEX`. */
const CHALLENGE_2_HEX =
  'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

// ---------------------------------------------------------------------
// Attack simulation
// ---------------------------------------------------------------------

describe('nonce-reuse attack — adversarial documentation', () => {
  // Shared setup. `password` is `new Uint8Array(0)` because Property 10
  // (test/property-10-password-no-op.test.ts) and the file-level
  // closure in `transcript.ts` together lock that `password` is a
  // no-op on the produced proof; the empty buffer is the structurally
  // simplest valid choice (`assertUint8ArrayLengthBetween(password,
  // 0, 4096, ...)` accepts length 0).
  const privateKey = hexToBytes(PRIVATE_KEY_HEX);
  const password = new Uint8Array(0);
  const r_bytes = hexToBytes(NONCE_HEX);
  const challenge1 = hexToBytes(CHALLENGE_1_HEX);
  const challenge2 = hexToBytes(CHALLENGE_2_HEX);

  // Derive `publicKey_bytes` the same way `compute-proof.ts` does
  // (Requirement 11.2): `publicKey = pointToBytes(BASE.multiply(x))`,
  // where `x = scalarFromBytesLE(privateKey)` (already in `[1, L)`
  // for this hand-picked input, so no `reduceScalar` is needed).
  // We need this for the verifier-side `computeFiatShamirScalar`
  // calls below.
  const x_actual = scalarFromBytesLE(privateKey);
  const publicKey = pointToBytes(BASE.multiply(x_actual));

  // Run the two proofs once, share results across the three `it`
  // blocks. Each proof goes through the SHARED `computeProofCore`
  // helper inside `compute-proof.ts` — the same code path the
  // production `computeProof` exercises — but with the live RNG
  // bypassed by the `__forTesting__` hook.
  const proof1 = __forTesting__.computeProofWithFixedNonce(
    privateKey,
    password,
    challenge1,
    r_bytes,
  );
  const proof2 = __forTesting__.computeProofWithFixedNonce(
    privateKey,
    password,
    challenge2,
    r_bytes,
  );

  it('precondition: same nonce produces byte-identical R commitments across two challenges', () => {
    // Slice `R_bytes` out of each 64-byte proof. This is the
    // commitment segment per the encoding contract (Requirement
    // 3.1: `proof = R_bytes || s_bytes`, 32 bytes each).
    const R1 = proof1.subarray(0, 32);
    const R2 = proof2.subarray(0, 32);

    // The hook re-derives `R = BASE.multiply(r)` where
    // `r = reduceScalar(scalarFromBytesLE(r_bytes))`. Since the
    // SAME `r_bytes` was passed to both calls, `r` is the same,
    // so `R` is the same Edwards point, and `pointToBytes(R)` is
    // the same canonical 32-byte encoding. Asserting byte equality
    // here makes the attack precondition explicit: without nonce
    // reuse there is no shared `R`, and the s1 - s2 = (c1 - c2)·x
    // simplification would not apply.
    expect(R1.length).toBe(32);
    expect(R2.length).toBe(32);
    expect(Array.from(R1)).toEqual(Array.from(R2));
  });

  it('precondition: distinct challenges produce distinct Fiat-Shamir scalars c1 !== c2', () => {
    // Recompute `c1` and `c2` from `(R, publicKey, challenge_i)`
    // using the SAME `computeFiatShamirScalar` function the prover
    // and verifier use — the single transcript pinning point in
    // `transcript.ts`. Both proofs share the same `R_bytes` (per
    // the previous `it` block); the only varying input is the
    // challenge.
    const R_bytes = proof1.subarray(0, 32);
    const c1 = computeFiatShamirScalar(R_bytes, publicKey, challenge1);
    const c2 = computeFiatShamirScalar(R_bytes, publicKey, challenge2);

    // SHA-512 applied to two distinct 96-byte transcripts produces
    // distinct 64-byte digests in the random-oracle model, and
    // `reduceScalar` mod L preserves that distinctness with
    // overwhelming probability. The hand-picked `CHALLENGE_1_HEX`
    // and `CHALLENGE_2_HEX` are not adversarial constructions, so
    // the assertion holds. If a future change to the transcript
    // construction were to ever produce `c1 === c2` for these
    // inputs, the recovery math in the next block would fail with
    // a divide-by-zero on `(c1 - c2) mod L`, and the test would
    // surface that defect.
    expect(c1).not.toBe(c2);
  });

  it('attack: recovers the secret scalar x from two proofs sharing a nonce', () => {
    // ----- Step 1: extract the response scalars s1, s2 -----
    //
    // Slice `s_bytes` out of each 64-byte proof and decode each as
    // a little-endian bigint. The hook produced these via
    // `reduceScalar(r + c_i · x)` per Requirement 3.4, so each
    // value is already in `[0, L)`; no further reduction is
    // needed.
    const s1 = scalarFromBytesLE(proof1.subarray(32, 64));
    const s2 = scalarFromBytesLE(proof2.subarray(32, 64));

    // ----- Step 2: recompute the Fiat-Shamir scalars c1, c2 -----
    //
    // Same as the previous `it` block. `R_bytes` is shared between
    // the two proofs (locked by the first `it` block).
    const R_bytes = proof1.subarray(0, 32);
    const c1 = computeFiatShamirScalar(R_bytes, publicKey, challenge1);
    const c2 = computeFiatShamirScalar(R_bytes, publicKey, challenge2);

    // ----- Step 3: defensively re-check c1 !== c2 -----
    //
    // The previous `it` block locks this contract, but a defensive
    // re-assertion here makes the test fail with a clear message
    // (rather than a divide-by-zero in `modInverse`) on the
    // off-chance that future input choices regress into a
    // collision. `c1 === c2` would imply `(c1 - c2) mod L === 0n`,
    // which has no modular inverse.
    expect(c1).not.toBe(c2);

    // ----- Step 4: solve for x via the s1 - s2 = (c1 - c2)·x identity -----
    //
    // From the two response equations
    //   s1 ≡ (r + c1 · x) (mod L)
    //   s2 ≡ (r + c2 · x) (mod L)
    // subtracting cancels `r`:
    //   s1 - s2 ≡ (c1 - c2) · x   (mod L)
    // and so
    //   x ≡ (s1 - s2) · (c1 - c2)^(-1)   (mod L).
    //
    // The `((... % L) + L) % L` bracketing on `s1 - s2` and
    // `c1 - c2` normalizes a potentially-negative bigint
    // difference into the canonical `[0, L)` representative
    // before the multiplication; without this, the bigint product
    // would be the correct value modulo L but not the canonical
    // representative, and the final `===` against `x_actual`
    // (which IS canonical) would silently fail.
    const ds = ((s1 - s2) % L + L) % L;
    const dcInverse = modInverse(c1 - c2, L);
    const x_recovered = (ds * dcInverse) % L;

    // ----- Step 5: assert the recovered scalar IS the secret -----
    //
    // The recovered scalar MUST equal `x_actual = scalarFromBytesLE(
    // privateKey)`. If this assertion ever fails, the attack
    // simulation has gone wrong (either the hook did not actually
    // reuse the nonce, or the verifier-side Fiat-Shamir derivation
    // does not match the prover-side, or the modular-inverse
    // helper has a bug) — every one of those is itself a
    // regression worth catching.
    //
    // The assertion is on `bigint` values, NOT on byte arrays.
    // `bigint` `===` is exact value equality and is permitted under
    // the audit-guard's forbidden-data identifier set
    // (Requirement 3.8). The check is not on secret material
    // either: this is test-only code, with a deliberately reused
    // nonce, demonstrating the underlying mathematics rather than
    // exercising a production code path.
    expect(x_recovered).toBe(x_actual);
  });
});
