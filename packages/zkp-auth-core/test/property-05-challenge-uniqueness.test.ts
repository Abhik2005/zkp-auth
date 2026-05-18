// @zkp-auth/core — Property 5: Challenge uniqueness
//
// Property 5: Challenge uniqueness
// Validates: Requirements 2.3
// See design.md → "Correctness Properties → Property 5" and
//     design.md → "Components and Interfaces → challenge.ts" and
//     requirements.md → "Requirement 2: Challenge Generation, AC 2.3".
//
// For any fixed valid `sessionId`, across `N >= 1000` invocations of
// `generateChallenge(sessionId)` against a real CSPRNG, all returned
// challenges are pairwise distinct.
//
// We exercise this contract concretely at `N = 1000`. Each invocation
// runs against the LIVE Node CSPRNG (no mocks) — collisions here would
// indicate a real entropy bug, not a fast-check artifact. Per the
// design's "Statistical tests" section, the probability of a spurious
// collision under a healthy CSPRNG drawing 32-byte (256-bit) outputs is,
// by the birthday bound, `<= N^2 / 2^256 ~= 10^6 / 2^256 ~= 10^-71` for
// `N = 1000`. A failure is therefore unambiguously a correctness
// problem, not statistical noise.
//
// Structure (mirrors `property-02-keypair-uniqueness.test.ts`):
//
//   * The "iteration" lives inside the property body: we run
//     `generateChallenge(FIXED_SESSION_ID)` in a tight loop, push each
//     returned 32-byte challenge into a `Set<string>` keyed by hex, and
//     assert `seen.size === N`. The property is therefore an
//     *aggregate* over `N` trials — "no collisions across N draws" —
//     rather than a per-draw property.
//
//   * Because the meaningful loop is inside the body, fast-check is run
//     with `numRuns: 1`. Running it more than once would burn CSPRNG
//     output without adding any signal to the assertion. We still wrap
//     the body in `fc.assert(fc.property(fc.constant(null), () => ...))`
//     for stylistic parity with `property-01-keypair-invariant.test.ts`
//     and `property-02-keypair-uniqueness.test.ts` — the wrapper is the
//     convention this suite uses for every "Property N" test, even when
//     (as here) the property has no fast-check-driven inputs.
//
//   * `bytesToHex` is defined inline rather than imported from
//     `@noble/curves/utils.js`. The 32-byte → 64-char hex conversion is
//     trivial and keeping the helper local keeps this test file's audit
//     surface tight: only `../src/challenge.js` is imported from the
//     library under test, and no `@noble/*` import appears in this file.
//
//   * A `Set<string>` of 1000 64-char hex entries is ~64KB of strings;
//     trivially within memory. Wall-clock cost is dominated by 1000
//     CSPRNG draws of 32 bytes each, which is well within Vitest's
//     default per-test timeout, so no custom `timeout` is set on the
//     `it(...)` block.
//
// Choice of fixed `sessionId`: the SPECIFIC value below is arbitrary.
// Property 4 (task 6.2) already locks the contract that
// `generateChallenge`'s output is independent of `sessionId`, so any
// valid `sessionId` proves Property 5 equally well. We pick a stable,
// self-documenting 31-byte ASCII value (within the [1, 256] length
// bound from Requirement 2.2) so that any failing-stack trace makes the
// test's identity obvious.
//
// TDD red-phase note: `../src/challenge.js` does NOT exist yet — it is
// produced by task 6.5. Until then, this import will fail to resolve
// and the test will not run. That is the expected state for task 6.3.
// The package's `tsconfig.json` `"include": ["src/**/*"]` excludes
// `test/**/*` from typecheck scope, so `tsc --noEmit` remains clean
// even with this unresolved test-only import.

import { describe, it } from 'vitest';
import fc from 'fast-check';

import { generateChallenge } from '../src/challenge.js';

const N = 1000;

// Arbitrary but stable valid `sessionId` (31 bytes, within the
// [1, 256] length bound from Requirement 2.2). The specific value does
// not matter for Property 5 — Property 4 separately locks
// `sessionId`-independence — so we choose a self-documenting string
// that surfaces clearly in failing-test output.
const FIXED_SESSION_ID: Uint8Array = new TextEncoder().encode(
  'zkp-auth-property-05-uniqueness',
);

/**
 * Encode a `Uint8Array` as a lowercase hex string. Used solely to give
 * each challenge a stable, hashable key for the uniqueness `Set`.
 *
 * Defined inline to keep this test file independent of `@noble/*` —
 * the 32-byte → 64-char conversion is a one-liner and the local
 * definition is its own audit-surface argument.
 */
function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

describe('Property 5: Challenge uniqueness', () => {
  it(`emits ${N} distinct challenges across ${N} invocations with a fixed sessionId`, () => {
    fc.assert(
      fc.property(fc.constant(null), () => {
        const seen = new Set<string>();
        for (let i = 0; i < N; i += 1) {
          const challenge = generateChallenge(FIXED_SESSION_ID);
          seen.add(bytesToHex(challenge));
        }
        return seen.size === N;
      }),
      { numRuns: 1 },
    );
  });
});
