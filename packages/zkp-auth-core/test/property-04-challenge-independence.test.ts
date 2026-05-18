// @zkp-auth/core — Property 4: Challenge independence from `sessionId`
//
// Property 4: Challenge independence from `sessionId`
// Validates: Requirements 2.5
// See design.md → "Correctness Properties → Property 4" and
//     design.md → "Components and Interfaces → challenge.ts" and
//     requirements.md → "Requirement 2: Challenge Generation, AC 2.5".
//
// For any two valid `sessionId` values `s1`, `s2` with `s1 ≠ s2`, and for
// any fixed CSPRNG output sequence, `generateChallenge(s1)` and
// `generateChallenge(s2)` produce byte-identical outputs. Equivalently:
// the returned challenge is a deterministic function of the RNG output
// alone and does NOT depend on `sessionId` in any way (Requirement 2.5).
//
// Why mocking is essential here:
//   Without a mock, every `generateChallenge` call draws fresh bytes from
//   the live CSPRNG, so two calls yield two distinct outputs WHATEVER the
//   implementation does with `sessionId`. That proves nothing about
//   whether `sessionId` is mixed into the output. By pinning
//   `randomBytes32` to return the SAME fixed 32-byte buffer on every
//   call, we strip away CSPRNG variability so the only remaining input
//   that could possibly affect the output is `sessionId`. If two distinct
//   `sessionId` values now produce two byte-identical challenges, then
//   `sessionId` is definitively NOT a function input — which is exactly
//   the contract Requirement 2.5 / Property 4 demand.
//
// We use `vi.hoisted` to declare the mock RNG up front so the factory
// passed to `vi.mock` can reference it. `vi.mock` factories are hoisted
// above imports, so a normal module-scope variable would be undefined at
// factory-execution time; `vi.hoisted` is the canonical Vitest pattern
// for this (mirrors property-13).
//
// Pair-rejection technique: we use `fc.tuple(arb, arb).filter(...)` to
// reject equal `(s1, s2)` pairs. Collisions are vanishingly rare for
// random `Uint8Array(1..256)` inputs (most likely at length 1, ~1/256
// per draw), so `fast-check` will almost never need to skip; `filter`
// keeps the property body free of a `fc.pre` branch and shrinks
// acceptably for our purposes.
//
// TDD red-phase note: `../src/challenge.js` does NOT exist yet — it is
// produced by task 6.5. Until then, this import will fail to resolve
// and the test will not run. That is the expected state for task 6.2.
// The package's `tsconfig.json` `"include": ["src/**/*"]` excludes
// `test/**/*` from typecheck scope, so `tsc --noEmit` remains clean
// even with this unresolved test-only import.

import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import fc from 'fast-check';

// `vi.hoisted` lets the `vi.mock` factory below reference `rngMock` even
// though the factory is hoisted to the top of the module by Vitest. We
// use a non-generic `vi.fn()` and configure typing via
// `mockImplementation` to avoid the `Type '() => Uint8Array' does not
// satisfy the constraint 'any[]'` diagnostic that the single-generic
// `vi.fn<() => Uint8Array>()` form produces in this codebase's TS
// version.
const rngMock = vi.hoisted(() => ({
  randomBytes32: vi.fn(),
}));

vi.mock('../src/rng.js', () => ({
  randomBytes32: rngMock.randomBytes32,
}));

// TODO(11.1): replace the inline `fc.uint8Array(...)` arbitrary below
// with the shared `arbSessionId` from `./arbitraries.js` once task 11.1
// lands. The bounds (`minLength: 1`, `maxLength: 256`) are taken
// directly from Requirements 2.1 / 2.2 and the design's Property 4
// statement, and must match `arbSessionId` once it is introduced.
//
// Imported AFTER `vi.mock` for reader clarity. Vitest's hoisting handles
// the actual ordering at runtime; the visual order here matches the
// human-reader's mental model of "set up the mock, then import the unit
// under test".
import { generateChallenge } from '../src/challenge.js';

// The fixed 32-byte CSPRNG output every mocked `randomBytes32` call
// returns. The specific byte value (0xAB) is arbitrary — any constant
// 32-byte pattern would prove the property equally well. What matters
// is that the buffer is 32 bytes long (so the implementation's length
// expectation is satisfied) and IDENTICAL across calls (so any
// observed difference between two challenges can only come from
// `sessionId`).
const FIXED_RNG_OUTPUT: Uint8Array = new Uint8Array(32).fill(0xab);

// Per-byte numeric equality on `Uint8Array` views is fine in test files:
// byte values are numbers in `[0, 255]`, not secret material, and the
// audit guard from task 13.1 scans `src/**/*.ts` only — `test/**/*.ts`
// is explicitly out of its scope.
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

describe('Property 4: Challenge independence from sessionId', () => {
  beforeEach(() => {
    // Return a FRESH COPY of the fixed buffer on every call. This
    // guarantees that even if the implementation mutates (e.g.
    // zero-fills) the returned buffer after extracting its bytes, the
    // next call sees an unchanged source. Without this, a defensive
    // wipe in the implementation could cause the second
    // `generateChallenge` call to receive different bytes than the
    // first — confounding the property under test.
    rngMock.randomBytes32.mockImplementation(
      (): Uint8Array => new Uint8Array(FIXED_RNG_OUTPUT),
    );
  });

  afterEach(() => {
    // Reset both implementation and call history so each `it` (and
    // any future appended block) starts with a fresh mock state.
    rngMock.randomBytes32.mockReset();
  });

  it('two distinct sessionId values produce byte-identical challenges when CSPRNG output is fixed', () => {
    fc.assert(
      fc.property(
        // TODO(11.1): swap each inline arbitrary for the shared
        // `arbSessionId` from `./arbitraries.js` once task 11.1 lands.
        fc
          .tuple(
            fc.uint8Array({ minLength: 1, maxLength: 256 }),
            fc.uint8Array({ minLength: 1, maxLength: 256 }),
          )
          .filter(([s1, s2]) => !equalBytes(s1, s2)),
        ([sessionId1, sessionId2]) => {
          const c1 = generateChallenge(sessionId1);
          const c2 = generateChallenge(sessionId2);

          // Sanity: both outputs must be the contracted shape
          // (Requirement 2.1, Property 3). If either is malformed the
          // independence claim is moot.
          if (!(c1 instanceof Uint8Array) || c1.length !== 32) return false;
          if (!(c2 instanceof Uint8Array) || c2.length !== 32) return false;

          // The independence claim itself (Requirement 2.5,
          // Property 4): with the CSPRNG pinned, two distinct
          // `sessionId` inputs MUST yield byte-identical challenges.
          return equalBytes(c1, c2);
        },
      ),
      { numRuns: 100 },
    );
  });
});
