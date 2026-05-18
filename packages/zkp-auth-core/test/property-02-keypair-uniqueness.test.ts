// @zkp-auth/core — Property 2: Key pair uniqueness
//
// Property 2: Key pair uniqueness
// Validates: Requirements 1.4
// See design.md → "Correctness Properties → Property 2" and
//     design.md → "Components and Interfaces → keypair.ts".
//
// For any `N >= 1000` independent invocations of `generateKeyPair()`, all
// emitted `privateKey` values are pairwise distinct.
//
// We exercise this contract concretely at `N = 1000`. Each invocation runs
// against the LIVE Node CSPRNG (no mocks) — collisions here would indicate a
// real entropy bug, not a fast-check artifact. Per the design's
// "Statistical tests" section, the probability of a spurious collision under
// a healthy CSPRNG drawing 32-byte secrets is far below `2^-200` for
// `N = 1000`, so a failure is unambiguously a correctness problem.
//
// Structure:
//
//   * The "iteration" lives inside the property body: we run
//     `generateKeyPair()` in a tight loop, push each `privateKey` into a
//     `Set<string>` keyed by hex, and assert `seen.size === N`. The
//     property is therefore an *aggregate* over `N` trials — "no collisions
//     across N draws" — rather than a per-draw property.
//
//   * Because the meaningful loop is inside the body, fast-check is run
//     with `numRuns: 1`. Running it more than once would burn CSPRNG output
//     without adding any signal to the assertion. We still wrap the body in
//     `fc.assert(fc.property(fc.constant(null), () => ...))` for stylistic
//     parity with `property-01-keypair-invariant.test.ts` and with later
//     property files — the wrapper is the convention this suite uses for
//     every "Property N" test, even when (as here) the property has no
//     fast-check-driven inputs.
//
//   * `bytesToHex` is defined inline rather than imported from
//     `@noble/curves/utils.js`. The 32-byte → 64-char hex conversion is
//     trivial and keeping the helper local keeps this test file's
//     audit surface tight: only `../src/keypair.js` is imported from the
//     library under test, and no `@noble/*` import appears in this file.
//
//   * A `Set<string>` of 1000 64-char hex entries is ~64KB of strings;
//     trivially within memory. Wall-clock cost is dominated by 1000
//     ed25519 base-point multiplications (one per `generateKeyPair`
//     invocation, inside `BASE.multiply(n)`); on commodity hardware this
//     is well within Vitest's default per-test timeout, so no custom
//     `timeout` is set on the `it(...)` block.

import { describe, it } from 'vitest';
import fc from 'fast-check';

import { generateKeyPair } from '../src/keypair.js';

const N = 1000;

/**
 * Encode a `Uint8Array` as a lowercase hex string. Used solely to give
 * each `privateKey` a stable, hashable key for the uniqueness `Set`.
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

describe('Property 2: Key pair uniqueness', () => {
  it(`emits ${N} distinct privateKey values across ${N} invocations`, () => {
    fc.assert(
      fc.property(fc.constant(null), () => {
        const seen = new Set<string>();
        for (let i = 0; i < N; i += 1) {
          const { privateKey } = generateKeyPair();
          seen.add(bytesToHex(privateKey));
        }
        return seen.size === N;
      }),
      { numRuns: 1 },
    );
  });
});
