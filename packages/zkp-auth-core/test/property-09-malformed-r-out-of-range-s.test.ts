// @zkp-auth/core — Property 9: `verifyProof` returns `false` (does not
// throw) for malformed `R` or out-of-range `s`
//
// Property 9: `verifyProof` returns `false` (does not throw) for
//             malformed `R` or out-of-range `s`
// Validates: Requirements 4.7, 4.8
// See design.md → "Components and Interfaces → verify-proof.ts"
//     (steps 4 and 5 of the verify algorithm) and
//     design.md → "Key design decisions → 5–6" (oracle-avoidance: the
//     verify path silently returns `false` for attacker-chosen inputs
//     and throws only for caller-side `publicKey` errors) and
//     requirements.md → "Requirement 4.7" (malformed `R` returns
//     `false`, NOT throw, to deny an oracle that distinguishes
//     "malformed `R`" from "well-formed but mathematically invalid"
//     proofs) and "Requirement 4.8" (out-of-range `s` returns `false`,
//     NOT throw, for the same reason — `s_bytes` is attacker-chosen
//     proof material).
//
// For an honest `(publicKey, challenge)` pair derived from a valid
// `privateKey`, and any honest 32-byte `R_bytes` and 32-byte `s_bytes`
// derived from the production proof construction:
//
//   • Substituting `R_bytes` with arbitrary bytes that
//     `pointFromBytesSoft(...) === null` (i.e. fail Edwards point
//     decoding) MUST cause `verifyProof(publicKey, challenge,
//     malformed_R || honest_s)` to return `false` and to NOT throw.
//   • Substituting `s_bytes` with the little-endian encoding of any
//     bigint in `[L, 2^256)` MUST cause `verifyProof(publicKey,
//     challenge, honest_R || out_of_range_s)` to return `false` and to
//     NOT throw.
//
// Why an "honest" `(publicKey, challenge, R_bytes, s_bytes)` tuple is
// required as the canvas:
//   The verify algorithm's failure modes are layered. For a malformed
//   `R` to be observed in isolation, every OTHER input on the verify
//   path must be well-formed: `publicKey` must decode (else a different
//   error path — Requirement 4.5's `InvalidInputError` — is taken),
//   `challenge` must be `Uint8Array(32)` (else Requirement 4.6 throws),
//   and `proof.length === 64` must hold (else Requirement 4.6 throws
//   on `INVALID_PROOF`). Likewise for an isolated out-of-range `s`:
//   `publicKey`, `challenge`, AND `R_bytes` must all be well-formed so
//   the only failure mode the verify path can trip on is the `s >= L`
//   range check.
//
//   We obtain the honest tuple by routing through
//   `__forTesting__.computeProofWithFixedNonce` (the test-only nonce
//   hook from `compute-proof.ts`, design.md ~line 1085). Pinning the
//   nonce gives a deterministic 64-byte proof from which we slice out
//   well-formed `R_bytes` (`[0, 32)`) and well-formed `s_bytes`
//   (`[32, 64)`) per the proof encoding contract (Requirement 3.1).
//   `publicKey = pointToBytes(BASE.multiply(scalarFromBytesLE(privateKey)))`
//   uses the SAME scalar derivation as `computeProof` (Requirement
//   11.1), guaranteeing the honest proof would round-trip true for
//   THIS `(publicKey, challenge)` pair if its byte material were not
//   tampered with — that's the canvas the malformed/out-of-range
//   substitutions are painted onto.
//
// Why `expect(...).not.toThrow()` AND `result === false`:
//   Requirement 4.7/4.8 has two halves: (a) the function returns
//   `false`, and (b) the function does NOT throw. Asserting the
//   absence of a throw via `expect(() => { result = verifyProof(...) })
//   .not.toThrow()` and then asserting `result === false` covers both
//   halves explicitly. A version of the property that only checked
//   `verifyProof(...) === false` would miss the "does not throw"
//   half if the implementation regressed — a thrown error would
//   surface as a different test failure mode (an uncaught exception
//   in the property body) rather than as the specific contract
//   violation Requirement 4.7/4.8 names.
//
// Why no `vi.mock` is used here:
//   The properties under test are pure functions of `verifyProof`'s
//   input bytes; no CSPRNG variability is involved on the verify path
//   (the prover-side nonce variability is removed by the test-only
//   nonce hook on the prover side, not by mocking `rng.ts`). Keeping
//   the test mock-free reduces the audit surface and the risk of a
//   hoisted-mock interaction with the parallel test runner.
//
// Why we filter rather than reject in the property body:
//   For malformed `R`, we use `fc.uint8Array(...).filter(b =>
//   pointFromBytesSoft(b) === null)` rather than generating arbitrary
//   bytes and `fc.pre`-skipping the well-formed cases. Filtering keeps
//   shrinker quality intact: if the property fails, fast-check shrinks
//   within the *filtered* input space (only malformed `R_bytes`),
//   which is the input space the property is making a claim about.
//   Roughly half of random 32-byte strings decode successfully on
//   Ed25519 (the y-coordinate must satisfy the curve equation and
//   admit a square root for `x`), so the filter rejection rate is
//   tolerable at `numRuns: 100`. For out-of-range `s`, no filter is
//   needed: the constraint `s ∈ [L, 2^256)` is enforceable directly on
//   the `bigInt` arbitrary, since `2^256 > L`.
//
// TDD red-phase note: `../src/verify-proof.js` does NOT exist yet —
// it is produced by task 8.2. Until then, this import will fail to
// resolve and the test will not run. That is the expected state for
// task 8.1. The package's `tsconfig.json` `"include": ["src/**/*"]`
// excludes `test/**/*` from typecheck scope, so `tsc --noEmit`
// remains clean even with this unresolved test-only import.
//
// Per-byte construction of `Uint8Array` views is fine in test files:
// byte values are numbers in `[0, 255]`, not secret material, and the
// audit guard from task 13.1 scans `src/**/*.ts` only — `test/**/*.ts`
// is explicitly out of its scope.

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';

import { numberToBytesLE } from '@noble/curves/utils.js';

import { verifyProof } from '../src/verify-proof.js';
import { __forTesting__ as cpForTesting } from '../src/compute-proof.js';
import {
  L,
  BASE,
  pointToBytes,
  scalarFromBytesLE,
  pointFromBytesSoft,
} from '../src/encoding.js';

// TODO(11.1): replace each inline arbitrary below with the shared
// arbitraries from `./arbitraries.js` once task 11.1 lands. The
// bounds (`[1, L)` for scalars; `length === 32` for nonce buffers
// and challenges; `length ∈ [0, 64]` for password; `[L, 2^256)` for
// out-of-range `s`) are taken directly from the design's Property 9
// statement and from Requirements 3.1–3.7 and 4.7–4.8, and must
// match the shared arbitraries once those are introduced.
const arbValidPrivateKey: fc.Arbitrary<Uint8Array> = fc
  .bigInt({ min: 1n, max: L - 1n })
  .map((n) => numberToBytesLE(n, 32));

// `r_bytes` for the honest-proof construction. Same shape as
// `arbValidPrivateKey`: a 32-byte little-endian encoding of a scalar
// in `[1, L)`. The `__forTesting__` hook's contract (design.md
// ~line 1085) is that `r_bytes` decodes to a valid nonce.
const arbValidNonceBytes: fc.Arbitrary<Uint8Array> = fc
  .bigInt({ min: 1n, max: L - 1n })
  .map((n) => numberToBytesLE(n, 32));

const arbChallenge32: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 32,
  maxLength: 32,
});

// Password is opaque metadata to `__forTesting__.computeProofWithFixedNonce`
// (Requirements 3.7, 11.1, Property 10). We use a modest length bound
// of 64 here — the maximum is 4096 per Requirement 3.7, but Property 9
// is not making a claim about password handling, so any in-range
// password is fine. Keeping the bound small reduces shrinker work.
const arbPassword: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 0,
  maxLength: 64,
});

// Random 32-byte arrays that fail Ed25519 point decoding. The filter
// keeps only those bytes for which `pointFromBytesSoft` returns
// `null`, which is precisely the input space Requirement 4.7's
// claim is about. Acceptance rate is roughly 50% on random 32-byte
// inputs, comfortable for `numRuns: 100`.
const arbInvalidRBytes: fc.Arbitrary<Uint8Array> = fc
  .uint8Array({ minLength: 32, maxLength: 32 })
  .filter((b) => pointFromBytesSoft(b) === null);

// Out-of-range `s` per Requirement 4.8: any little-endian-encoded
// scalar in `[L, 2^256)`. The interval is non-empty since `L < 2^253
// < 2^256`. `numberToBytesLE(n, 32)` throws on `n >= 2^256`, so the
// `max: (1n << 256n) - 1n` bound keeps every generated case strictly
// representable in 32 bytes.
const arbOutOfRangeSBytes: fc.Arbitrary<Uint8Array> = fc
  .bigInt({ min: L, max: (1n << 256n) - 1n })
  .map((n) => numberToBytesLE(n, 32));

describe('Property 9 — verifyProof rejects malformed R and out-of-range s without throwing', () => {
  describe('malformed R bytes (cannot decode to Edwards point)', () => {
    it('returns false and does not throw', () => {
      fc.assert(
        fc.property(
          arbValidPrivateKey,
          arbPassword,
          arbChallenge32,
          arbValidNonceBytes,
          arbInvalidRBytes,
          (privateKey, password, challenge, r_bytes, malformed_R_bytes) => {
            // Derive the honest publicKey from privateKey using the
            // SAME scalar derivation `computeProof` uses
            // (Requirement 11.1). The honest tuple's `publicKey`
            // must be well-formed so the verify path's failure mode
            // is isolated to the malformed-`R` branch (Requirement
            // 4.7), not to the `INVALID_PUBLIC_KEY` branch
            // (Requirement 4.5).
            const x = scalarFromBytesLE(privateKey);
            const publicKey = pointToBytes(BASE.multiply(x));

            // Build an honest 64-byte proof so we can extract a
            // well-formed `s_bytes` to pair with the malformed
            // `R_bytes`. The `__forTesting__` hook makes a defensive
            // copy of `r_bytes` (compute-proof.ts ~line 470), so
            // re-using `r_bytes` across iterations of the property
            // body is safe.
            const honestProof = cpForTesting.computeProofWithFixedNonce(
              privateKey,
              password,
              challenge,
              r_bytes,
            );
            const honest_s_bytes = honestProof.subarray(32, 64);

            // Construct the tampered proof: malformed `R` || honest
            // `s`. Allocating a fresh 64-byte buffer (rather than
            // mutating `honestProof`) keeps the test free of
            // side-effects on shared values across the fast-check
            // body.
            const tampered = new Uint8Array(64);
            tampered.set(malformed_R_bytes, 0);
            tampered.set(honest_s_bytes, 32);

            // The two halves of Requirement 4.7: (a) does not throw,
            // (b) returns `false`. We capture the return value
            // through the closure rather than calling `verifyProof`
            // twice — calling it once preserves any internal-state
            // assumptions (there are none, but the principle stands)
            // and matches the structure prescribed by tasks.md.
            let result: boolean | undefined;
            expect(() => {
              result = verifyProof(publicKey, challenge, tampered);
            }).not.toThrow();
            expect(result).toBe(false);
          },
        ),
        { numRuns: 100 },
      );
    });
  });

  describe('out-of-range s (s >= L)', () => {
    it('returns false and does not throw', () => {
      fc.assert(
        fc.property(
          arbValidPrivateKey,
          arbPassword,
          arbChallenge32,
          arbValidNonceBytes,
          arbOutOfRangeSBytes,
          (privateKey, password, challenge, r_bytes, out_of_range_s_bytes) => {
            // Same canvas construction as the malformed-`R`
            // describe block: well-formed `publicKey`, well-formed
            // honest `R_bytes` extracted from a fixed-nonce honest
            // proof, with the only tampered field being `s_bytes`.
            const x = scalarFromBytesLE(privateKey);
            const publicKey = pointToBytes(BASE.multiply(x));

            const honestProof = cpForTesting.computeProofWithFixedNonce(
              privateKey,
              password,
              challenge,
              r_bytes,
            );
            const honest_R_bytes = honestProof.subarray(0, 32);

            // Construct the tampered proof: honest `R` || out-of-
            // range `s`. The verify path's `s >= L` check
            // (Requirement 4.8, design.md verify-step 5) is the only
            // failure mode reachable here — every other input on
            // the verify path is well-formed by construction.
            const tampered = new Uint8Array(64);
            tampered.set(honest_R_bytes, 0);
            tampered.set(out_of_range_s_bytes, 32);

            // The two halves of Requirement 4.8: (a) does not throw,
            // (b) returns `false`.
            let result: boolean | undefined;
            expect(() => {
              result = verifyProof(publicKey, challenge, tampered);
            }).not.toThrow();
            expect(result).toBe(false);
          },
        ),
        { numRuns: 100 },
      );
    });
  });
});
