// @zkp-auth/core — Property 10: `password` is a no-op on the produced proof
//
// Property 10: `password` is a no-op on the produced proof (mocked nonce)
// Validates: Requirements 3.3, 9.3, 11.1, 11.5, 11.6
// See design.md → "Correctness Properties → Property 10" and
//     design.md → "Components and Interfaces → compute-proof.ts" and
//     design.md → "External API Surface" (the `__forTesting__` hook
//       description) and
//     requirements.md → "Requirement 3.3" (password is documentational
//       only, never mixed into proof material), "Requirement 9.3"
//       (zero-knowledge: proof material independent of `password`),
//       "Requirement 11.1" (property-based testing), "Requirement 11.5"
//       and "Requirement 11.6" (test-only nonce hook for property
//       testing of nonce-randomized primitives).
//
// For any `privateKey: Uint8Array(32)` decoding to `x ∈ [1, L)`, any
// `challenge: Uint8Array(32)`, any fixed nonce `r ∈ [1, L)` injected
// via the `__forTesting__.computeProofWithFixedNonce` hook, and any
// two `password` values `p1`, `p2` (each a `Uint8Array` of length
// `≤ 4096`),
//
//   computeProofWithFixedNonce(privateKey, p1, challenge, r_bytes)
//     ===
//   computeProofWithFixedNonce(privateKey, p2, challenge, r_bytes)
//
// (byte-identical 64-byte proofs `R || s`).
//
// Why the `__forTesting__` hook is essential here:
//   The public `computeProof(privateKey, password, challenge)` draws
//   its nonce `r` from the live CSPRNG on every call. Two calls with
//   the same `(privateKey, challenge)` but different `password`
//   values would therefore yield two distinct `R = r·G` components
//   WHATEVER the implementation does with `password` — purely
//   because `r` was redrawn. That confounds the property: we cannot
//   distinguish "implementation correctly ignores `password`" from
//   "implementation mixes `password` in, but the CSPRNG masked it".
//   By injecting a fixed `r_bytes` via the test-only hook
//   (Requirements 11.5 and 11.6), we strip away CSPRNG variability
//   so the only remaining input that could possibly affect the
//   output is `password`. If two distinct `password` values now
//   produce two byte-identical proofs, then `password` is
//   definitively NOT a function input — which is exactly the
//   contract Requirements 3.3 / 9.3 / Property 10 demand.
//
// Why no `vi.mock` is used here:
//   Unlike Property 4 (challenge independence from `sessionId`), which
//   pins the live `randomBytes32` via `vi.mock`, Property 10 uses the
//   parameter-injection pattern instead: the `__forTesting__` hook
//   accepts `r_bytes` as an explicit argument, sidestepping
//   `randomBytes32()` at the source. This is simpler and avoids the
//   hoisted-mock machinery — the hook itself is the seam.
//
// Why we do NOT filter `p1 !== p2`:
//   Unlike Property 4 (which requires `s1 ≠ s2` to make "independence"
//   non-trivial), Property 10 is even STRONGER when `p1 === p2`:
//   identical inputs trivially produce identical outputs. Allowing
//   `p1 === p2` does not weaken the property — it merely adds some
//   redundant cases. Omitting a `filter`/`fc.pre` therefore preserves
//   shrinker quality without any loss of property strength.
//
// TDD red-phase note: `../src/compute-proof.js` does NOT exist yet —
// it is produced by task 7.6. Until then, this import will fail to
// resolve and the test will not run. That is the expected state for
// task 7.1. The package's `tsconfig.json` `"include": ["src/**/*"]`
// excludes `test/**/*` from typecheck scope, so `tsc --noEmit`
// remains clean even with this unresolved test-only import.
//
// Per-byte numeric equality on `Uint8Array` views is fine in test
// files: byte values are numbers in `[0, 255]`, not secret material,
// and the audit guard from task 13.1 scans `src/**/*.ts` only —
// `test/**/*.ts` is explicitly out of its scope.

import { describe, it } from 'vitest';
import fc from 'fast-check';

import { numberToBytesLE } from '@noble/curves/utils.js';

import { L } from '../src/encoding.js';
import { __forTesting__ } from '../src/compute-proof.js';

// Local byte-equality helper, inlined to mirror the style of
// `property-04-challenge-independence.test.ts`. Importing a
// constant-time `equalBytes` from `@noble/curves/utils.js` is
// unnecessary here: this is non-secret test data and we do not need
// timing safety in tests.
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// TODO(11.1): replace each inline arbitrary below with the shared
// `arbValidPrivateKey`, `arbChallenge32`, and `arbPassword` from
// `./arbitraries.js` once task 11.1 lands. The bounds (`[1, L)` for
// scalars; `length ∈ [0, 4096]` for `password`; `length === 32` for
// `challenge`) are taken directly from the design's Property 10
// statement and from Requirements 3.1–3.3, and must match the shared
// arbitraries once those are introduced.
const arbValidPrivateKey: fc.Arbitrary<Uint8Array> = fc
  .bigInt({ min: 1n, max: L - 1n })
  .map((n) => numberToBytesLE(n, 32));

// TODO(11.1): replace with shared `arbValidNonceBytes` from
// `./arbitraries.js` once task 11.1 lands. Same shape as
// `arbValidPrivateKey`: a 32-byte little-endian encoding of a scalar
// in `[1, L)`. The hook's contract (design.md ~line 1085) is that
// `r_bytes` decodes to a valid nonce; sampling from `[1, L)` keeps
// every generated case inside the contracted input space.
const arbValidNonceBytes: fc.Arbitrary<Uint8Array> = fc
  .bigInt({ min: 1n, max: L - 1n })
  .map((n) => numberToBytesLE(n, 32));

// TODO(11.1): replace with shared `arbChallenge32` from
// `./arbitraries.js` once task 11.1 lands.
const arbChallenge32: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 32,
  maxLength: 32,
});

// TODO(11.1): replace with shared `arbPassword` from
// `./arbitraries.js` once task 11.1 lands. Length bounds `[0, 4096]`
// match the design's Property 10 statement and Requirement 3.3.
const arbPassword: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 0,
  maxLength: 4096,
});

describe('Property 10: password is a no-op on the produced proof', () => {
  it('two arbitrary password values produce byte-identical 64-byte proofs when (privateKey, challenge, r_bytes) are fixed', () => {
    fc.assert(
      fc.property(
        arbValidPrivateKey,
        arbChallenge32,
        arbValidNonceBytes,
        arbPassword,
        arbPassword,
        (privateKey, challenge, r_bytes, p1, p2) => {
          const proof1 = __forTesting__.computeProofWithFixedNonce(
            privateKey,
            p1,
            challenge,
            r_bytes,
          );
          const proof2 = __forTesting__.computeProofWithFixedNonce(
            privateKey,
            p2,
            challenge,
            r_bytes,
          );

          // Sanity: both outputs must be the contracted shape (64
          // bytes = `R || s`, design.md ~line 517 / Requirement 3.6).
          // If either is malformed the no-op claim is moot.
          if (!(proof1 instanceof Uint8Array) || proof1.length !== 64) {
            return false;
          }
          if (!(proof2 instanceof Uint8Array) || proof2.length !== 64) {
            return false;
          }

          // The no-op claim itself (Requirements 3.3, 9.3, Property
          // 10): with `(privateKey, challenge, r_bytes)` pinned, two
          // arbitrary `password` inputs MUST yield byte-identical
          // proofs. Note: we deliberately do NOT pre-filter
          // `p1 !== p2` — see header comment for rationale.
          return equalBytes(proof1, proof2);
        },
      ),
      { numRuns: 100 },
    );
  });
});
