// @zkp-auth/core — Property 14: `timingSafeEqualBytes` returns `false` on
// length-mismatched inputs without throwing
//
// Property 14: `timingSafeEqualBytes` handles unequal lengths without throwing
// Validates: Requirements 5.3
// See design.md → "Components and Interfaces → compare.ts —
//     Constant-time byte equality" (the wrapper specification, which
//     mandates a synchronous `false` return when `a.length !== b.length`),
//     design.md → "Correctness Properties → Property 14" (this property's
//     entry in the property catalogue), and
//     requirements.md → "Requirement 5: Non-Functional — Timing-Safe
//     Comparisons", AC 5.3 ("IF Timing_Safe_Equal is invoked with two
//     `Uint8Array` arguments of unequal length, THEN THE Core_Library
//     SHALL treat them as unequal without throwing — length is not secret
//     in this protocol; we wrap the call to normalize").
//
// For any pair of `Uint8Array`s `a`, `b` with `a.length !== b.length`,
// `timingSafeEqualBytes(a, b)` MUST:
//   1. NOT throw, and
//   2. return exactly `false`.
//
// Why this property exists at all (Requirement 5.3 rationale):
//   The underlying primitive `node:crypto.timingSafeEqual` throws a
//   synchronous `RangeError("Input buffers must have the same byte
//   length")` when its two arguments differ in length. That throw is
//   itself a side channel — it is observably different from the boolean
//   `true`/`false` outcomes the function produces on equal-length
//   inputs, and a caller that fails to wrap the call in `try`/`catch`
//   will leak the length-mismatch fact to its own callers via an
//   exception path with different timing characteristics than the
//   normal return path. `compare.ts` defends against this by adding an
//   explicit `if (a.length !== b.length) return false;` guard at the
//   JS layer BEFORE delegating to `timingSafeEqual`, converting the
//   would-be `RangeError` into a uniform `false` return. Length is
//   public information in this protocol (it is part of the encoding
//   contract — proofs are 64 bytes, public keys are 32 bytes,
//   challenges are 32 bytes, etc.), so a synchronous `false` is the
//   safe and ergonomic normalization.
//
// What this test locks down:
//   This is the simplest and most surgical of the property suite — it
//   pins a single line of `compare.ts` (`if (a.length !== b.length)
//   return false;`). If a future refactor were to delete or reorder
//   that guard so the `timingSafeEqual` call is reached with mismatched
//   lengths, fast-check would observe a thrown `RangeError` and the
//   `expect(...).not.toThrow()` half of the assertion would fail
//   immediately. Likewise, if the guard returned `true` (or anything
//   other than `false`) on a length mismatch, the `expect(result).toBe(false)`
//   half would fail. Both halves are required — covering only the
//   "doesn't throw" half would let a buggy `return true` pass; covering
//   only the "returns false" half would let an exception-eating wrapper
//   pass.
//
// Scope of this property:
//   This property is intentionally narrow. It says NOTHING about the
//   equal-length case — that is the domain of `node:crypto.timingSafeEqual`
//   itself and is exercised implicitly throughout the suite by the
//   round-trip and tampering properties (Properties 6 and 7). Property 14
//   exists solely to lock the length-tolerance half of `compare.ts`'s
//   contract, which is the half that `crypto.timingSafeEqual` does NOT
//   provide on its own.
//
// Inline arbitrary (purely local — `arbitraries.ts` does not currently
// list a "two unequal-length Uint8Array" arbitrary, and task 11.1 has
// no entry to extract this into shared form, so this stays inline by
// design):
//   Two `Uint8Array`s with `length ∈ [0, 64]`, filtered via `fc.pre`
//   to keep only pairs where `a.length !== b.length`. The `[0, 64]`
//   bound is comfortably larger than any byte-array width the library
//   actually uses (32 for keys/challenges/scalars, 64 for proofs) and
//   includes 0 to exercise the empty-array boundary. `fc.pre` may
//   short-circuit a small number of iterations when fast-check happens
//   to draw two arrays of equal length; that is expected and harmless,
//   and fast-check's per-`numRuns` accounting handles it natively.

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';

import { timingSafeEqualBytes } from '../src/compare.js';

describe('Property 14 — timingSafeEqualBytes returns false for length-mismatched inputs without throwing', () => {
  it('returns false and does not throw on unequal lengths', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 0, maxLength: 64 }),
        fc.uint8Array({ minLength: 0, maxLength: 64 }),
        (a, b) => {
          // Constrain the input space to the only case this property
          // talks about: pairs whose lengths differ. fast-check's
          // `fc.pre` aborts the current iteration as a non-failure
          // when the predicate is false, so equal-length draws are
          // simply skipped rather than counted as passing on
          // irrelevant input. The probability of a same-length draw
          // is roughly 1/65 per case (lengths uniform in [0, 64]),
          // so the skip rate is low enough that 100 `numRuns`
          // comfortably yields ~98 effective property checks.
          fc.pre(a.length !== b.length);

          // Two-stage assertion. We capture the function's return
          // value INSIDE the `expect(() => ...).not.toThrow()`
          // callback so that:
          //
          //   (a) If `timingSafeEqualBytes` throws (which would
          //       indicate the `compare.ts` length-guard has been
          //       removed or reordered such that the underlying
          //       `node:crypto.timingSafeEqual` is reached with
          //       mismatched lengths and raises `RangeError`), the
          //       `not.toThrow()` matcher fails the test
          //       immediately with the actual thrown error, giving
          //       a clear diagnostic.
          //
          //   (b) If `timingSafeEqualBytes` returns normally, we
          //       still need to verify the RETURN VALUE is exactly
          //       `false` — not `true`, not `undefined`, not a
          //       truthy object, not a `Buffer`. Capturing into
          //       `result` and asserting `toBe(false)` afterwards
          //       gives strict equality (`Object.is`), which
          //       distinguishes `false` from every other falsy
          //       value.
          //
          // The `let result: boolean | undefined` typing reflects
          // the lifecycle: before the callback runs, `result` is
          // unset; after the callback runs (assuming no throw), it
          // is the boolean returned by the function under test. If
          // the function were to throw, `result` would remain
          // `undefined` and the subsequent `toBe(false)` assertion
          // would fail loudly — though the `not.toThrow()` matcher
          // would already have failed first, surfacing the throw as
          // the primary diagnostic.
          let result: boolean | undefined;
          expect(() => {
            result = timingSafeEqualBytes(a, b);
          }).not.toThrow();
          expect(result).toBe(false);
        },
      ),
      { numRuns: 100 },
    );
  });
});
