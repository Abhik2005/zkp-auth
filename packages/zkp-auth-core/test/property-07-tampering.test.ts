// @zkp-auth/core — Property 7: soundness — single-bit tampering of
// `R`, `s`, `publicKey`, or `challenge` rejects
//
// Property 7: Soundness — single-bit tampering of `R`, `s`,
//             `publicKey`, or `challenge` rejects
// Validates: Requirements 4.11
// See design.md → "Correctness Properties → Property 7" and
//     design.md → "Components and Interfaces → verify-proof.ts" (the
//                 verification equation `s · G == R + c · publicKey`
//                 whose left- and right-hand sides this property
//                 desynchronizes via a single-bit flip on any one of
//                 its four inputs) and
//     design.md → "Key design decisions → 5" (asymmetric error model:
//                 the verify path returns `false` for malformed
//                 proof material BUT throws `InvalidInputError` for
//                 a malformed or identity-decoding `publicKey`) and
//     requirements.md → "Requirement 4.11" (any single-bit flip of
//                 `R_bytes`, `s_bytes`, `publicKey`, or `challenge`
//                 MUST cause `verifyProof` to return `false`;
//                 `password` is intentionally omitted from the
//                 enumeration because Property 10 establishes that
//                 `password` is a no-op on the produced proof).
//
// THE SOUNDNESS CLAIM
//
// For any honest `(publicKey, challenge, proof)` triple — i.e. one
// where `proof = computeProof(privateKey, password, challenge)` and
// `publicKey = pointToBytes(BASE.multiply(scalarFromBytesLE(privateKey)))`
// — flipping a single bit in any one of `R_bytes` (the first 32 bytes
// of `proof`), `s_bytes` (the last 32 bytes of `proof`), `publicKey`,
// or `challenge` MUST cause `verifyProof` to reject the resulting
// tuple. This is the textbook soundness probe for a Schnorr proof:
// any single-bit difference in `(R, s, publicKey, challenge)`
// perturbs the verification equation
//
//   s · G == R + c · publicKey
//
// (with `c = int_LE(SHA-512(R_bytes || publicKey || challenge)) mod L`,
// per `transcript.ts`) by a non-trivial group element. The discrete-log
// hardness assumption tells us that no efficient adversary can
// arrange for `(R, s)` to satisfy that perturbed equation except with
// negligible probability — and this property exercises 100 random
// bit-flip positions across all four target buffers, which is plenty
// to surface any regression that accidentally accepts a tampered
// proof (e.g. a verifier that strips the high bit of `challenge`
// before hashing, or one that compares only the first 16 bytes of
// the equation's two sides).
//
// PROPERTY 7 vs. PROPERTIES 6, 8, 9, 10 — RESPONSIBILITY SPLIT
//
// The four-property cluster around the verify path is intentionally
// partitioned so each property locks one slice of the contract:
//
//   • Property 6 (test/property-06-proof-roundtrip.test.ts): an
//     UNTAMPERED honest proof verifies as `true`. This is the
//     "completeness" half of soundness — without it, Property 7
//     would be vacuously satisfied (a verifier that returns `false`
//     unconditionally rejects every tampered proof too).
//
//   • Property 7 (THIS file): a SINGLE-BIT-TAMPERED honest proof
//     verifies as `false`. This is the "soundness" half — it locks
//     that the `true` Property 6 establishes is fragile under any
//     bit flip in `(R, s, publicKey, challenge)`. Together,
//     Properties 6 and 7 form a complete round-trip lock.
//
//   • Property 8 (test/property-08-input-validation.test.ts): inputs
//     drawn from explicit "invalid families" — non-`Uint8Array`,
//     wrong length, `publicKey` decoding to identity, etc. — throw
//     `InvalidInputError` with stable `.code`. This lives BELOW
//     Property 7's claim space: Property 7 only addresses inputs
//     that are still well-formed enough to reach the verify
//     equation.
//
//   • Property 9 (test/property-09-malformed-r-out-of-range-s.test.ts):
//     attacker-chosen proof material that would fail Edwards point
//     decoding for `R_bytes`, or whose `s` decodes to `>= L`,
//     returns `false` (does not throw). Property 9 addresses the
//     POST-decode-but-pre-equation rejection paths — a different
//     slice from Property 7, which addresses the equation-fails
//     rejection path.
//
//   • Property 10 (test/property-10-password-no-op.test.ts): `password`
//     is opaque — bit-flipping `password` does not change the
//     produced proof. This is why Requirement 4.11 explicitly
//     excludes `password` from the tamper-target set in Property 7:
//     a `password` bit flip is a no-op on the proof and would
//     therefore verify as `true` (not `false`), which would falsify
//     a naive "any bit flip rejects" property if `password` were
//     included.
//
// THE ASYMMETRIC ERROR MODEL: WHY `publicKey` TAMPERING NEEDS A SOFT-SKIP
//
// `verifyProof`'s contract (design "Key design decisions → 5",
// codified in `verify-proof.ts`) is asymmetric across its four
// inputs:
//
//   • Tampering `R_bytes` always produces a `false` return:
//     - if the flip lands in a position that breaks Edwards point
//       decoding, `pointFromBytesSoft` returns `null` and
//       `verify-proof.ts` step 4 returns `false` (Requirement 4.7);
//     - if the flip preserves a valid encoding but produces a
//       different point, `R` is well-formed but the verification
//       equation fails and step 8 returns `false` (Requirement 4.9).
//
//   • Tampering `s_bytes` always produces a `false` return:
//     - if the flip pushes `s` out of `[0, L)`, step 5 returns
//       `false` (Requirement 4.8);
//     - if the flip stays in range but produces a different scalar,
//       the equation fails and step 8 returns `false`.
//
//   • Tampering `challenge` always produces a `false` return: it
//     does not affect any decode step, but it changes the
//     Fiat-Shamir scalar `c` in step 6, which desynchronizes the
//     equation and step 8 returns `false`.
//
//   • Tampering `publicKey` is the asymmetric case (Requirement 4.5):
//     - if the flip preserves a valid Edwards encoding and
//       non-identity, the equation fails and step 8 returns `false`
//       — this is the slice Property 7 makes a claim about;
//     - BUT if the flip produces bytes that fail Edwards decode (a
//       non-canonical y-coordinate, an off-curve point, etc.) OR
//       that decode to the identity point `O = (0, 1)`,
//       `verify-proof.ts` steps 2 and 2-identity throw
//       `InvalidInputError` with `code === 'INVALID_PUBLIC_KEY'`
//       (Requirement 4.5). Those throw paths are out-of-scope for
//       Property 7 — they are LOCKED by Properties 8 and 9 — and
//       this file MUST NOT treat them as Property 7 violations.
//
// Concretely: when the tamper target is `publicKey` and the flipped
// bytes happen to fall into the "fails decode or decodes to identity"
// region of `Uint8Array(32)`, `verifyProof` throws an
// `InvalidInputError` rather than returning `false`. We soft-skip
// those iterations: the property body catches the throw, asserts it
// is the EXPECTED typed error (`InvalidInputError` with code
// `'INVALID_PUBLIC_KEY'`) so a regression that produced a different
// exception class would still surface here, then `return`s early.
// fast-check treats a `return` from a property body the same as a
// passing iteration, which gives us the soft-skip semantics
// fast-check itself does not provide (`fc.pre` is checked BEFORE the
// property body executes; here we cannot know whether the flipped
// `publicKey` will decode without actually attempting the decode).
//
// We do NOT use `fc.pre` here because the predicate "this flipped
// publicKey will fail decode" requires running `pointFromBytesSoft`
// to evaluate, and we deliberately want to exercise the full
// `verifyProof` path on every iteration — both to catch regressions
// in the throw-vs-return decision and to keep this property a
// faithful soundness probe rather than a filtered subset of one.
//
// WHY `password` IS NOT IN THE TAMPER-TARGET SET
//
// Requirement 4.11 explicitly excludes `password`, with cross-
// reference to Requirement 9.3 (the no-op-on-tamper test). The
// rationale: under Requirement 11.1, scalar derivation is
// `x = int_LE(privateKey) mod L` and does NOT depend on `password`;
// under Requirement 8.1, the Fiat-Shamir transcript is
// `R || publicKey || challenge` and does NOT include `password`.
// Therefore bit-flipping `password` between the prover side and the
// verifier side is invisible to the proof: the produced 64 bytes
// are byte-identical (Property 10), and `verifyProof` does not
// take `password` as an argument at all. A property that included
// `password` in the tamper-target set would assert "verify rejects
// a `password` bit flip" — which is FALSE under the v1 protocol
// (verify accepts the proof regardless of `password`, because
// `password` was never part of the proof material). Excluding
// `password` here keeps Property 7 honest with respect to the v1
// contract.
//
// TODO(11.1): replace each inline arbitrary below with the shared
// arbitraries from `./arbitraries.js` once task 11.1 lands. The
// bounds (`[1, L)` for the private-key scalar, `length === 32` for
// `challenge` and `publicKey`, `length ∈ [0, 64]` for `password`,
// `byteIndex ∈ [0, 31]` and `bitIndex ∈ [0, 7]` for the bit-flip
// position on the 32-byte targets, `byteIndex ∈ [0, 63]` for the
// 64-byte `proof` target) are taken from design "Testing Strategy →
// Custom arbitraries" and from the requirement IDs above, and must
// match the shared arbitraries once those are introduced.
//
// Per-byte construction of `Uint8Array` views is fine in test files:
// byte values are numbers in `[0, 255]`, not secret material, and
// the audit guard from task 13.1 scans `src/**/*.ts` only —
// `test/**/*.ts` is explicitly out of its scope.

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';

import { numberToBytesLE } from '@noble/curves/utils.js';

import { computeProof } from '../src/compute-proof.js';
import { verifyProof } from '../src/verify-proof.js';
import {
  L,
  BASE,
  scalarFromBytesLE,
  pointToBytes,
} from '../src/encoding.js';
import { InvalidInputError } from '../src/errors.js';

// 32-byte little-endian encoding of a scalar `n ∈ [1, L)`. Mirrors
// the contract of the shared `arbValidPrivateKey` arbitrary
// (task 11.1) and matches Requirement 11.4's "private key in `[1, L)`"
// condition that `computeProof` enforces.
const arbValidPrivateKey: fc.Arbitrary<Uint8Array> = fc
  .bigInt({ min: 1n, max: L - 1n })
  .map((n) => numberToBytesLE(n, 32));

// Modest password length bound: any in-range `Uint8Array` is a valid
// input for `computeProof` per Requirement 3.7, and Property 7 makes
// no claim about password handling at any particular size (Property
// 10 covers the password-no-op invariant). Keeping the bound small
// reduces shrinker work.
const arbPassword: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 0,
  maxLength: 64,
});

// 32-byte challenge per Requirement 4.6. Uniform random bytes; the
// challenge is a public input and one of Property 7's tamper
// targets.
const arbChallenge32: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 32,
  maxLength: 32,
});

// One of the four tamper targets enumerated in Requirement 4.11.
// `password` is intentionally NOT in this set — see the
// "WHY `password` IS NOT IN THE TAMPER-TARGET SET" section in the
// file header for the rationale.
const arbTamperTarget: fc.Arbitrary<'R' | 's' | 'publicKey' | 'challenge'> =
  fc.constantFrom('R' as const, 's' as const, 'publicKey' as const, 'challenge' as const);

describe('Property 7 — soundness: single-bit tampering of R, s, publicKey, or challenge rejects', () => {
  it('any single-bit flip on R, s, publicKey, or challenge causes verifyProof to return false (or throw InvalidInputError on out-of-scope publicKey decodes)', () => {
    fc.assert(
      fc.property(
        arbValidPrivateKey,
        arbPassword,
        arbChallenge32,
        arbTamperTarget,
        // `bitIndex ∈ [0, 7]`: which bit of the chosen byte to flip.
        fc.integer({ min: 0, max: 7 }),
        // `rawByteIndex ∈ [0, 63]`: an upper-bound-safe index that we
        // narrow per target below. Generating it once at this width
        // and clamping per target keeps the arbitrary signature
        // simple and lets fast-check's shrinker work uniformly.
        fc.integer({ min: 0, max: 63 }),
        (privateKey, password, challenge, target, bitIndex, rawByteIndex) => {
          // Construct the honest tuple. `publicKey` is derived using
          // the SAME scalar derivation `compute-proof.ts` uses
          // internally (Requirement 11.1: `x = int_LE(privateKey)`,
          // no password mixing) — see Property 6's file header for
          // the full rationale on why we derive publicKey by hand
          // rather than route through `generateKeyPair()`.
          const x = scalarFromBytesLE(privateKey);
          const publicKey = pointToBytes(BASE.multiply(x));
          const proof = computeProof(privateKey, password, challenge);

          // Apply the single-bit flip to a defensive copy of the
          // chosen target buffer, leaving the other three buffers
          // honest. The byteIndex bound is narrowed per target:
          // `proof` is 64 bytes (`R` lives in `[0, 32)`, `s` in
          // `[32, 64)`); `publicKey` and `challenge` are 32 bytes
          // each. We mutate copies so subsequent fast-check
          // iterations see fresh inputs.
          let pk = publicKey;
          let ch = challenge;
          let pf = proof;
          if (target === 'R') {
            const byteIndex = rawByteIndex % 32; // R lives in proof[0..32)
            pf = new Uint8Array(proof);
            pf[byteIndex] ^= 1 << bitIndex;
          } else if (target === 's') {
            const byteIndex = (rawByteIndex % 32) + 32; // s lives in proof[32..64)
            pf = new Uint8Array(proof);
            pf[byteIndex] ^= 1 << bitIndex;
          } else if (target === 'publicKey') {
            const byteIndex = rawByteIndex % 32;
            pk = new Uint8Array(publicKey);
            pk[byteIndex] ^= 1 << bitIndex;
          } else {
            // target === 'challenge'
            const byteIndex = rawByteIndex % 32;
            ch = new Uint8Array(challenge);
            ch[byteIndex] ^= 1 << bitIndex;
          }

          // Invoke the verify path. The expected outcome split is:
          //   • target ∈ { 'R', 's', 'challenge' }      → return false (always)
          //   • target === 'publicKey', flipped bytes
          //     remain a non-identity decodable point → return false
          //   • target === 'publicKey', flipped bytes
          //     fail decode or decode to identity      → throw
          //                                              InvalidInputError
          //                                              (out-of-scope for
          //                                              Property 7; locked
          //                                              by Properties 8/9)
          //
          // We catch the throw and soft-skip the iteration ONLY for
          // the publicKey-tampering case AND ONLY when the throw is
          // the expected typed error. A throw of any OTHER class
          // (or any throw at all on the `R` / `s` / `challenge`
          // tampering paths) is a contract violation we want
          // fast-check to surface — so we re-throw it.
          let result: boolean | undefined;
          try {
            result = verifyProof(pk, ch, pf);
          } catch (e) {
            if (
              target === 'publicKey' &&
              e instanceof InvalidInputError &&
              e.code === 'INVALID_PUBLIC_KEY'
            ) {
              // Soft-skip: the flipped publicKey landed in the
              // throw-region of the asymmetric error model. Property
              // 7's claim does not extend to this iteration —
              // Properties 8 and 9 cover it instead. fast-check
              // treats a `return` from the property body the same as
              // a passing iteration.
              return;
            }
            // Any other throw is a regression: re-throw so fast-check
            // surfaces it with the original counterexample.
            throw e;
          }

          // The Property 7 claim itself: for every tamper target and
          // every bit position that did NOT trip the asymmetric
          // throw above, `verifyProof` MUST return `false`. The
          // soundness of the underlying Schnorr construction
          // guarantees this with overwhelming probability across
          // 100 random tampers.
          expect(result).toBe(false);
        },
      ),
      { numRuns: 100 },
    );
  });
});
