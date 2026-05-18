// @zkp-auth/core — Property 11: Nonce freshness — distinct `R` across calls under live RNG
//
// Property 11: Nonce freshness — distinct `R` across calls under live RNG
// Validates: Requirements 3.2, 6.1
// See design.md → "Correctness Properties → Property 11" and
//     design.md → "Components and Interfaces → compute-proof.ts" and
//     requirements.md → "Requirement 3.2" (fresh nonce `r ∈ [1, L)` drawn
//       from a CSPRNG on every invocation; not derived from inputs; not
//       reused across invocations within the process — verified
//       statistically across N≥1000 calls in tests) and
//     requirements.md → "Requirement 6.1" (CSPRNG-drawn nonce on every
//       `computeProof` invocation).
//
// For any fixed valid `(privateKey, password, challenge)` triple, across
// `N >= 1000` independent invocations of
// `computeProof(privateKey, password, challenge)` against a real CSPRNG,
// all returned proofs have pairwise-distinct first-32-byte (`R`)
// components.
//
// We exercise this contract concretely at `N = 1000`. Each invocation
// runs against the LIVE Node CSPRNG (no mocks) — collisions in `R` here
// would indicate a real entropy / nonce-reuse bug, not a fast-check
// artifact. Per the design's "Statistical tests" section, the relevant
// entropy bound is on the nonce `r ∈ [1, L)` with `L ≈ 2^252`; since
// `R = r·G` is an injective encoding of `r` into the prime-order
// subgroup (the map `r ↦ r·G` is a bijection on `[1, L)`), the
// probability of a spurious `R` collision under a healthy CSPRNG is, by
// the birthday bound, `<= N^2 / L ~= 10^6 / 2^252 ~= 10^-71` for
// `N = 1000`. A failure is therefore unambiguously a correctness
// problem, not statistical noise.
//
// Structure (mirrors `property-05-challenge-uniqueness.test.ts` and
// `property-02-keypair-uniqueness.test.ts`):
//
//   * The "iteration" lives inside the property body: we run
//     `computeProof(FIXED_PRIVATE_KEY, FIXED_PASSWORD, FIXED_CHALLENGE)`
//     in a tight loop, extract `proof.subarray(0, 32)` (the `R`
//     component — the first 32 bytes of the 64-byte `R || s` proof, per
//     Requirement 3.1), push each into a `Set<string>` keyed by hex,
//     and assert `seen.size === N`. The property is therefore an
//     *aggregate* over `N` trials — "no `R` collisions across N draws"
//     — rather than a per-draw property.
//
//   * Because the meaningful loop is inside the body, fast-check is run
//     with `numRuns: 1`. Running it more than once would burn CSPRNG
//     output without adding any signal to the assertion. We still wrap
//     the body in `fc.assert(fc.property(fc.constant(null), () => ...))`
//     for stylistic parity with `property-02-keypair-uniqueness.test.ts`
//     and `property-05-challenge-uniqueness.test.ts` — the wrapper is
//     the convention this suite uses for every "Property N" test, even
//     when (as here) the property has no fast-check-driven inputs.
//
//   * `bytesToHex` is defined inline rather than imported from
//     `@noble/curves/utils.js`. The 32-byte → 64-char hex conversion is
//     trivial and keeping the helper local keeps this test file's
//     audit surface tight: only `../src/compute-proof.js` is imported
//     from the library under test, and no `@noble/*` import appears in
//     this file.
//
//   * No `vi.mock` / no mocking primitives are imported. Property 11 is
//     specifically a claim about the LIVE CSPRNG — mocking the RNG
//     would falsify the experiment. (Property 10 covers the
//     mocked-nonce sibling claim that `password` does not influence
//     the proof; Property 12 covers the mocked-nonce claim that no
//     input influences `R`.)
//
//   * A `Set<string>` of 1000 64-char hex entries is ~64KB of strings;
//     trivially within memory. Wall-clock cost is dominated by 1000
//     ed25519 base-point multiplications inside `computeProof`
//     (one per invocation, computing `R = r·G`); on commodity hardware
//     this is well within Vitest's default per-test timeout, so no
//     custom `timeout` is set on the `it(...)` block.
//
// Choice of fixed `(privateKey, password, challenge)`: the SPECIFIC
// values below are arbitrary. Property 11 is about *nonce freshness* —
// i.e. that the `r` value drawn fresh from the CSPRNG on each call
// yields a distinct `R = r·G`. Any valid `(privateKey, password,
// challenge)` triple proves the property equally well. We pick stable,
// self-documenting values so failing-stack traces make the test's
// identity obvious.
//
//   - `FIXED_PRIVATE_KEY` is the 32-byte little-endian encoding of the
//     scalar `2`, well within the contracted `[1, L)` range from
//     Requirement 3.5. Declared as a literal `Uint8Array` to avoid
//     pulling in `numberToBytesLE` for a single one-shot encoding.
//   - `FIXED_PASSWORD` is an arbitrary 35-byte UTF-8 string. Property
//     10 (task 7.1) already locks `password`-independence of the proof
//     under a fixed nonce, so the specific `password` chosen here has
//     no bearing on whether Property 11 holds.
//   - `FIXED_CHALLENGE` is an all-`0x42` 32-byte buffer (non-zero,
//     self-documenting). Any 32-byte value satisfies Requirement 3.6.
//
// TDD red-phase note: `../src/compute-proof.js` does NOT exist yet —
// it is produced by task 7.6. Until then, this import will fail to
// resolve and the test will not run. That is the expected state for
// task 7.2. The package's `tsconfig.json` `"include": ["src/**/*"]`
// excludes `test/**/*` from typecheck scope, so `tsc --noEmit` remains
// clean even with this unresolved test-only import.

import { describe, it } from 'vitest';
import fc from 'fast-check';

import { computeProof } from '../src/compute-proof.js';

const N = 1000;

// Arbitrary but stable valid `privateKey`: the 32-byte little-endian
// encoding of the scalar `2` (byte 0 = 0x02, all other bytes = 0x00).
// `2 ∈ [1, L)` so this is well within the contracted range from
// Requirement 3.5. The specific value does not matter for Property 11
// — `R = r·G` depends on the CSPRNG-drawn nonce `r`, not on
// `privateKey` (Requirement 6.3) — so we pick the smallest non-trivial
// scalar to keep the literal compact and self-documenting.
const FIXED_PRIVATE_KEY: Uint8Array = (() => {
  const k = new Uint8Array(32);
  k[0] = 0x02;
  return k;
})();

// Arbitrary but stable valid `password` (35 bytes UTF-8, well within
// the [0, 4096] length bound from Requirement 3.7). Property 10
// separately locks `password`-independence of the proof under a fixed
// nonce, so the specific value chosen here does not affect Property
// 11. We use a self-documenting string that surfaces clearly in
// failing-test output.
const FIXED_PASSWORD: Uint8Array = new TextEncoder().encode(
  'zkp-auth-property-11-nonce-freshness',
);

// Arbitrary but stable valid `challenge` (32 bytes of 0x42, satisfying
// Requirement 3.6's `Uint8Array(32)` shape). Any 32-byte value works —
// `R = r·G` is independent of `challenge` (Requirement 6.3) — and
// all-`0x42` is non-zero and self-documenting in hex dumps.
const FIXED_CHALLENGE: Uint8Array = new Uint8Array(32).fill(0x42);

/**
 * Encode a `Uint8Array` as a lowercase hex string. Used solely to give
 * each `R` component a stable, hashable key for the uniqueness `Set`.
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

describe('Property 11: Nonce freshness — distinct R across calls under live RNG', () => {
  it(`emits ${N} distinct R components across ${N} computeProof invocations with a fixed (privateKey, password, challenge) triple`, () => {
    fc.assert(
      fc.property(fc.constant(null), () => {
        const seen = new Set<string>();
        for (let i = 0; i < N; i += 1) {
          const proof = computeProof(
            FIXED_PRIVATE_KEY,
            FIXED_PASSWORD,
            FIXED_CHALLENGE,
          );
          // First 32 bytes of the 64-byte `R || s` proof are the `R`
          // component (Requirement 3.1). `subarray` is a view, not a
          // copy — but we immediately hex-encode it, so the view's
          // backing buffer can be safely garbage-collected with the
          // `proof` reference at the end of each loop iteration.
          seen.add(bytesToHex(proof.subarray(0, 32)));
        }
        return seen.size === N;
      }),
      { numRuns: 1 },
    );
  });
});
