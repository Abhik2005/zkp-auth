// @zkp-auth/core — Property 12: Nonce determined only by RNG output, not by inputs
//
// Property 12: Nonce determined only by RNG output, not by inputs
// Validates: Requirements 6.3
// See design.md → "Correctness Properties → Property 12" and
//     design.md → "Components and Interfaces → compute-proof.ts" and
//     requirements.md → "Requirement 6.3" (the Core_Library SHALL NOT
//       derive the nonce deterministically from `privateKey`,
//       `password`, `challenge`, or any combination thereof).
//
// For any fixed RNG mock that returns the same 32-byte sequence on
// every call, and for any two valid input triples
// `(privateKey, password, challenge)` and
// `(privateKey', password', challenge')`,
//
//   computeProof(privateKey, password, challenge).subarray(0, 32)
//     ===
//   computeProof(privateKey', password', challenge').subarray(0, 32)
//
// (byte-identical 32-byte `R` components — the first half of the
// 64-byte `R || s` proof, per Requirement 3.1).
//
// Equivalently: holding the RNG output fixed, varying any input does
// not change `R`. This locks the contract that the nonce is NOT
// derived from the inputs (Requirement 6.3) and is determined SOLELY
// by what the CSPRNG returns.
//
// Why mocking the RNG is essential here:
//   The public `computeProof(privateKey, password, challenge)` draws
//   its nonce `r` from the live CSPRNG on every call (Requirement
//   6.1), so two calls — even with byte-identical inputs — would yield
//   two distinct `R = r·G` components purely because `r` was redrawn.
//   That confounds the property under test: we cannot distinguish
//   "implementation correctly ignores inputs when computing `r`" from
//   "implementation mixes inputs in, but the CSPRNG masked it". By
//   pinning `randomBytes32` to return the SAME fixed 32-byte buffer on
//   every call, we strip away CSPRNG variability so the only remaining
//   variables that could possibly affect `R` are the inputs. If two
//   distinct input triples now produce two byte-identical `R`
//   components, then the inputs are definitively NOT a function input
//   to the nonce derivation — which is exactly the contract
//   Requirement 6.3 / Property 12 demand.
//
// This test uses the same `vi.hoisted` + `vi.mock('../src/rng.js', ...)`
// pattern as `property-04-challenge-independence.test.ts`. Property 10
// (`property-10-password-no-op.test.ts`) takes a different route — it
// uses the `__forTesting__.computeProofWithFixedNonce` parameter
// hook — but Property 12's claim covers the public `computeProof` API
// itself, so we mock at the `rng.ts` boundary rather than bypassing it.
//
// Why we do NOT filter `(priv1, pwd1, chal1) !== (priv2, pwd2, chal2)`:
//   Unlike Property 4 (which requires `s1 ≠ s2` to make
//   "independence" non-trivial), Property 12 is even STRONGER when the
//   two triples are equal: identical inputs trivially produce
//   identical outputs. Allowing equal triples does not weaken the
//   property — it merely adds some redundant cases. Omitting a
//   `filter`/`fc.pre` therefore preserves shrinker quality without any
//   loss of property strength. (Same rationale as property-10's
//   no-filter on `(p1, p2)`.)
//
// TDD red-phase note: `../src/compute-proof.js` does NOT exist yet —
// it is produced by task 7.6. Until then, this import will fail to
// resolve and the test will not run. That is the expected state for
// task 7.3. The package's `tsconfig.json` `"include": ["src/**/*"]`
// excludes `test/**/*` from typecheck scope, so `tsc --noEmit` remains
// clean even with this unresolved test-only import.
//
// Per-byte numeric equality on `Uint8Array` views is fine in test
// files: byte values are numbers in `[0, 255]`, not secret material,
// and the audit guard from task 13.1 scans `src/**/*.ts` only —
// `test/**/*.ts` is explicitly out of its scope.

import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import fc from 'fast-check';

// `vi.hoisted` lets the `vi.mock` factory below reference `rngMock`
// even though the factory is hoisted to the top of the module by
// Vitest. We use a non-generic `vi.fn()` and configure typing via
// `mockImplementation` to avoid the `Type '() => Uint8Array' does not
// satisfy the constraint 'any[]'` diagnostic that the single-generic
// `vi.fn<() => Uint8Array>()` form produces in this codebase's TS
// version (mirrors property-04).
const rngMock = vi.hoisted(() => ({
  randomBytes32: vi.fn(),
}));

vi.mock('../src/rng.js', () => ({
  randomBytes32: rngMock.randomBytes32,
}));

// Imported AFTER `vi.mock` for reader clarity. Vitest's hoisting
// handles the actual ordering at runtime; the visual order here
// matches the human-reader's mental model of "set up the mock, then
// import the unit under test".
import { numberToBytesLE } from '@noble/curves/utils.js';

import { L } from '../src/encoding.js';
import { computeProof } from '../src/compute-proof.js';

// The fixed 32-byte CSPRNG output every mocked `randomBytes32` call
// returns. We deliberately pick the little-endian encoding of the
// scalar `2` (i.e. `[0x02, 0x00, 0x00, ..., 0x00]`) for two reasons:
//
//   1. Per design.md → "Components and Interfaces → compute-proof.ts"
//      step 4, the implementation derives the nonce as
//      `r = reduceScalar(scalarFromBytesLE(r_bytes))`, and per
//      Requirement 3.2 / 6.1 it MUST redraw if `r === 0n`. If our
//      fixed buffer happened to decode to a multiple of `L`, the
//      implementation would call `randomBytes32()` again and again
//      hoping for a non-zero scalar — but our mock returns the SAME
//      multiple-of-L every time, so the redraw loop would never
//      terminate. Picking a value definitively in `[1, L)` sidesteps
//      this entire concern: `2 ∈ [1, L)`, so `reduceScalar(2) === 2n`
//      and the implementation accepts on the first draw.
//   2. The encoding is self-documenting in any test failure dump: a
//      32-byte buffer that is `02 00 00 ... 00` is unambiguously "the
//      scalar 2 in LE", which makes it obvious to a reviewer that the
//      mock is well-formed and not the source of the failure.
//
// Any value in `[1, L)` would prove the property equally well — the
// specific scalar chosen has no bearing on whether Property 12 holds,
// because Property 12 is precisely the claim that `R = r·G` is a
// function of `r` (and hence of the RNG output) ALONE, with `r·G`
// computed identically across calls so long as `r` is identical.
const FIXED_RNG_OUTPUT: Uint8Array = numberToBytesLE(2n, 32);

// Per-byte numeric equality on `Uint8Array` views — see file header
// for why this is acceptable in test code. Inlined to mirror the
// style of `property-04-challenge-independence.test.ts` and
// `property-10-password-no-op.test.ts` rather than importing a
// constant-time `equalBytes` from `@noble/curves/utils.js`.
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
// `challenge`) are taken directly from the design's Property 12
// statement and from Requirements 3.1, 3.6, 3.7, and must match the
// shared arbitraries once those are introduced.
const arbValidPrivateKey: fc.Arbitrary<Uint8Array> = fc
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
// match the design's Property 12 statement and Requirement 3.7.
const arbPassword: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 0,
  maxLength: 4096,
});

describe('Property 12: Nonce determined only by RNG output, not by inputs', () => {
  beforeEach(() => {
    // Return a FRESH COPY of the fixed buffer on every call. This
    // guarantees that even if the implementation mutates (e.g.
    // zero-fills) the returned buffer after extracting its bytes —
    // see Requirement 6.4, which mandates exactly such a defensive
    // wipe — the next call sees an unchanged source. Without this,
    // the design's documented `r_bytes.fill(0)` post-use wipe would
    // cause the second `computeProof` call to receive an all-zero
    // buffer, which would fail the redraw guard and break the test.
    rngMock.randomBytes32.mockImplementation(
      (): Uint8Array => new Uint8Array(FIXED_RNG_OUTPUT),
    );
  });

  afterEach(() => {
    // Reset both implementation and call history so each `it` (and
    // any future appended block) starts with a fresh mock state.
    rngMock.randomBytes32.mockReset();
  });

  it('two arbitrary input triples produce byte-identical R components when CSPRNG output is fixed', () => {
    fc.assert(
      fc.property(
        arbValidPrivateKey,
        arbPassword,
        arbChallenge32,
        arbValidPrivateKey,
        arbPassword,
        arbChallenge32,
        (priv1, pwd1, chal1, priv2, pwd2, chal2) => {
          const proof1 = computeProof(priv1, pwd1, chal1);
          const proof2 = computeProof(priv2, pwd2, chal2);

          // Sanity: both outputs must be the contracted shape (64
          // bytes = `R || s`, design.md ~line 517 / Requirement 3.1).
          // If either is malformed the nonce-from-RNG-only claim is
          // moot.
          if (!(proof1 instanceof Uint8Array) || proof1.length !== 64) {
            return false;
          }
          if (!(proof2 instanceof Uint8Array) || proof2.length !== 64) {
            return false;
          }

          // First 32 bytes of the 64-byte `R || s` proof are the `R`
          // component (Requirement 3.1). `subarray` is a view, not a
          // copy — but we hand both views to `equalBytes` immediately
          // and never hold a reference past the property body, so the
          // backing buffers can be safely garbage-collected when the
          // body returns.
          const R1 = proof1.subarray(0, 32);
          const R2 = proof2.subarray(0, 32);

          // The nonce-from-RNG-only claim itself (Requirement 6.3,
          // Property 12): with the CSPRNG pinned, two arbitrary input
          // triples MUST yield byte-identical `R` components. Note:
          // we deliberately do NOT pre-filter
          // `(priv1, pwd1, chal1) !== (priv2, pwd2, chal2)` — see
          // header comment for rationale.
          return equalBytes(R1, R2);
        },
      ),
      { numRuns: 100 },
    );
  });
});
