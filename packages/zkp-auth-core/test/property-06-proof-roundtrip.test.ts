// @zkp-auth/core — Property 6: proof round-trip (honest prover, honest verifier)
//
// Property 6: Proof round-trip (honest prover, honest verifier)
// Validates: Requirements 3.1, 3.3, 3.4, 3.9, 4.1, 4.2, 4.3, 4.10,
//            8.1, 8.2, 8.3
// See design.md → "Correctness Properties → Property 6" and
//     design.md → "Components and Interfaces → compute-proof.ts" /
//                 "verify-proof.ts" (the prover/verifier pair whose
//                 round-trip equation `s · G == R + c · publicKey`
//                 this property locks) and
//     design.md → "External API Surface §B–§C" (the curve-math source
//                 of truth used by both `pointToBytes` and
//                 `BASE.multiply`) and
//     requirements.md → "Requirement 3.1" (proof shape `Uint8Array(64) =
//                 R || s`), "Requirement 3.3" (password is not folded
//                 into the transcript on the prover side), "Requirement
//                 3.4" (response `s = (r + c·x) mod L`), "Requirement
//                 3.9" (`computeProof` deterministic in `(privateKey,
//                 challenge)` modulo the CSPRNG-drawn nonce),
//                 "Requirement 4.1" (verify accepts only honest 64-byte
//                 proofs that satisfy the equation), "Requirement 4.2"
//                 (verify accepts the matching publicKey), "Requirement
//                 4.3" (verify recomputes `c` via the same Fiat-Shamir
//                 transcript the prover used), "Requirement 4.10"
//                 (verify returns `true` for honest proofs),
//                 "Requirement 8.1" (single Fiat-Shamir scalar pinned in
//                 transcript.ts), "Requirement 8.2" (verify recomputes
//                 the SAME `c`), "Requirement 8.3" (transcript inputs
//                 ordered `R || X || challenge`).
//
// THE ROUND-TRIP CLAIM
//
// For any random valid `(privateKey, password, challenge)` triple,
// deriving the matching `publicKey` from `privateKey` via the SAME
// scalar derivation `computeProof` uses internally
// (`x = int_LE(privateKey)`; `publicKey = pointToBytes(BASE.multiply(x))`,
// per Requirement 11.1's "no password mixing" and design "Components
// and Interfaces → compute-proof.ts" step 3), the proof produced by
// the honest prover MUST be accepted as `true` by the honest verifier:
//
//   proof = computeProof(privateKey, password, challenge)
//   proof.length === 64                                          (Requirement 3.1)
//   verifyProof(publicKey, challenge, proof) === true            (Requirements 4.1, 4.2, 4.10)
//
// Substituting the prover's construction (`R = r·G`, `s = (r + c·x) mod L`)
// into the verifier's equation `s · G == R + c · publicKey` and using
// `publicKey = x · G` gives `(r + c·x) · G == r·G + c · (x·G)`, which
// holds in the Edwards group. This is the textbook non-interactive
// Schnorr round-trip, and it is the FIRST test in the suite that
// exercises both `computeProof` and `verifyProof` together — so it is
// the first place a regression in either side, or a drift between the
// two sides' Fiat-Shamir construction (Requirement 8.2: verifier MUST
// recompute the same `c` the prover used), would surface.
//
// WHY WE DERIVE `publicKey` BY HAND, NOT VIA `generateKeyPair()`
//
// The natural-looking alternative would be to call `generateKeyPair()`
// inside the property body and feed both halves of the returned
// `{ privateKey, publicKey }` pair into the prover/verifier. We
// deliberately do NOT do this:
//
//   • `generateKeyPair()` uses rejection sampling against the CSPRNG
//     (`keypair.ts`'s `MAX_REJECTION_ITERATIONS = 256` loop). Every
//     call returns a fresh, independently-drawn `privateKey` —
//     unrelated to whatever `arbValidPrivateKey` produced for the
//     surrounding `fc.property` body. We would either have to
//     discard fast-check's `privateKey` (defeating the purpose of
//     the bigint-driven generator and its shrinker) or pass
//     fast-check's `privateKey` to `computeProof` AND
//     `generateKeyPair()`'s `publicKey` to `verifyProof`, which is
//     a category error: those two halves do NOT correspond to the
//     same secret.
//
//   • The specific 32-byte encoding fast-check produces for a
//     `bigInt({ min: 1n, max: L - 1n }).map(numberToBytesLE(_, 32))`
//     is the EXACT input we want `computeProof` to consume — it
//     covers the boundary scalars (`1n`, `L - 1n`, small primes)
//     that the shrinker can reach, and it lets a regression that
//     mishandles a particular byte pattern shrink down to a
//     minimal counterexample. Routing `privateKey` through
//     `generateKeyPair()` would replace fast-check's input with a
//     CSPRNG-drawn opaque buffer.
//
// So we derive the matching `publicKey` the way `compute-proof.ts`
// derives it internally on each call:
//
//   x = scalarFromBytesLE(privateKey)         // Requirement 11.1: no password mixing
//   publicKey = pointToBytes(BASE.multiply(x)) // RFC 8032 §5.1.2 canonical encoding
//
// This guarantees the prover's `x` and the verifier's `publicKey`
// agree on the exact same scalar — which is the prerequisite for the
// round-trip equation to hold. A drift between the prover's `x`
// derivation (e.g., a regression that suddenly DID mix `password`
// into `x`, contra Requirement 11.1) would surface here as a verify
// failure on every iteration: the verifier's `publicKey = x · G`
// would no longer correspond to the prover's secret. Property 6 is
// thus a single-test guard against any future password-into-scalar
// regression that Property 10 alone could miss (Property 10 only
// checks that two passwords produce the same proof under a fixed
// nonce — but if the implementation were modified to mix `password`
// into BOTH `x` and the public-key derivation, Property 10's
// invariant could still hold while breaking the round-trip; Property
// 6 catches that case directly).
//
// WHY ANY IN-RANGE `password` IS FINE
//
// `password` is opaque on the round-trip per Property 10
// (test/property-10-password-no-op.test.ts) — `computeProof`
// validates its shape (`Uint8Array`, length `[0, 4096]`,
// Requirement 3.7) and then ignores it. We therefore generate any
// in-range `password` here and rely on Property 10 to lock the
// "ignored" half of the contract independently. The bound
// `[0, 64]` chosen for this property's `arbPassword` is modest
// rather than the full `[0, 4096]` because the round-trip property
// is not making a claim about password handling at scale; the
// full-range exercise belongs in the fixed-vector regression test
// (task 11.3) where byte-exact behavior across the size spectrum
// is the explicit subject.
//
// TODO(11.1): replace each inline arbitrary below with the shared
// arbitraries from `./arbitraries.js` once task 11.1 lands. The
// bounds (`[1, L)` for the private-key scalar, `length === 32` for
// `challenge`, `length ∈ [0, 64]` for `password`) are taken from
// design "Testing Strategy → Custom arbitraries" and from the
// requirement IDs above, and must match the shared arbitraries
// once those are introduced.

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

// 32-byte little-endian encoding of a scalar `n ∈ [1, L)`. Mirrors
// the contract `arbValidPrivateKey` from design "Testing Strategy
// → Custom arbitraries" (task 11.1). The `bigInt({ min: 1n, max:
// L - 1n })` range matches Requirement 11.4's "private key in
// `[1, L)`" condition that `computeProof` enforces on its
// `privateKey` input.
const arbValidPrivateKey: fc.Arbitrary<Uint8Array> = fc
  .bigInt({ min: 1n, max: L - 1n })
  .map((n) => numberToBytesLE(n, 32));

// Modest password length bound: any in-range `Uint8Array` is a
// valid input for `computeProof` per Requirement 3.7, and the
// round-trip property does not make a claim about password handling
// at any particular size (full-range exercise is the fixed-vector
// regression test in task 11.3).
const arbPassword: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 0,
  maxLength: 64,
});

// 32-byte challenge per Requirement 3.6 (computeProof) and
// Requirement 4.6 (verifyProof). Uniform random bytes; the
// challenge is a public input on both sides of the round-trip.
const arbChallenge32: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 32,
  maxLength: 32,
});

describe('Property 6 — proof round-trip (honest prover, honest verifier)', () => {
  it('honest computeProof output verifies as true', () => {
    fc.assert(
      fc.property(
        arbValidPrivateKey,
        arbPassword,
        arbChallenge32,
        (privateKey, password, challenge) => {
          // Derive the matching publicKey using the SAME scalar
          // derivation `compute-proof.ts` step 2–3 uses internally
          // (Requirement 11.1: `x = int_LE(privateKey)`, no password
          // mixing). See the "WHY WE DERIVE `publicKey` BY HAND"
          // section in the file header for why we do not route
          // through `generateKeyPair()` here.
          const x = scalarFromBytesLE(privateKey);
          const publicKey = pointToBytes(BASE.multiply(x));

          // Honest prover step. `computeProof` draws a fresh nonce
          // `r ∈ [1, L)` from the live CSPRNG and assembles the
          // 64-byte proof `R || s`. The CSPRNG variability is
          // benign for this property — the round-trip equation
          // holds for ANY valid `r`, so we do not need (and do not
          // use) the `__forTesting__` nonce hook here.
          const proof = computeProof(privateKey, password, challenge);

          // Requirement 3.1: proof is a `Uint8Array` of length 64.
          // The `instanceof` check is the same `assertUint8Array`
          // shape contract `verifyProof` will re-validate
          // internally — locking it explicitly here gives a clearer
          // failure mode if a future regression silently changed
          // the prover's return type.
          expect(proof).toBeInstanceOf(Uint8Array);
          expect(proof.length).toBe(64);

          // Honest verifier step. With the matching `(publicKey,
          // challenge)` pair, the verification equation
          // `s · G == R + c · publicKey` holds by construction
          // (Requirements 4.1, 4.2, 4.3, 4.10), and the verifier
          // returns `true` via `timingSafeEqualBytes` over the
          // canonical RFC 8032 encodings of both sides
          // (Requirement 4.4).
          const result = verifyProof(publicKey, challenge, proof);
          expect(result).toBe(true);
        },
      ),
      { numRuns: 100 },
    );
  });
});
