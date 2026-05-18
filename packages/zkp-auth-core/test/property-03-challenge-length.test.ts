// @zkp-auth/core — Property 3: Challenge structural invariant
//
// Property 3: Challenge structural invariant
// Validates: Requirements 2.1
// See design.md → "Correctness Properties → Property 3" and
//     design.md → "Components and Interfaces → challenge.ts" and
//     requirements.md → "Requirement 2: Challenge Generation, AC 2.1".
//
// For any `sessionId: Uint8Array` with `1 <= sessionId.length <= 256`,
// `generateChallenge(sessionId)` returns a `Uint8Array` of exactly
// length 32. Per Requirement 2.1 the bytes are CSPRNG-drawn; per
// Requirement 2.5 / design Property 4 the bytes are independent of
// `sessionId`. THIS file asserts only the structural half of that
// contract — `instanceof Uint8Array` and `length === 32`. Distribution
// independence is covered separately by Property 4 (task 6.2) and
// uniqueness by Property 5 (task 6.3).
//
// `fast-check` drives the property over `numRuns: 100` invocations of
// `generateChallenge` against the LIVE Node CSPRNG (no mocks). Each run
// receives a fresh `sessionId` from the input arbitrary; the
// `Uint8Array(32)` shape contract must hold for every one.
//
// TDD red-phase note: `../src/challenge.js` does NOT exist yet — it is
// produced by task 6.5. Until then, this import will fail to resolve
// and the test will not run. That is the expected state for task 6.1.
// The package's `tsconfig.json` `"include": ["src/**/*"]` excludes
// `test/**/*` from typecheck scope, so `tsc --noEmit` remains clean
// even with this unresolved test-only import.

import { describe, it } from 'vitest';
import fc from 'fast-check';

// TODO(11.1): replace the inline `fc.uint8Array(...)` arbitrary below
// with the shared `arbSessionId` from `./arbitraries.js` once task 11.1
// lands. The bounds (`minLength: 1`, `maxLength: 256`) are taken
// directly from Requirement 2.1 / 2.2 and the design's Property 3
// statement, and must match `arbSessionId` once it is introduced.
import { generateChallenge } from '../src/challenge.js';

describe('Property 3: Challenge structural invariant', () => {
  it('every emitted challenge is a Uint8Array of length 32', () => {
    fc.assert(
      fc.property(
        // TODO(11.1): swap this inline arbitrary for the shared
        // `arbSessionId` from `./arbitraries.js` once task 11.1 lands.
        fc.uint8Array({ minLength: 1, maxLength: 256 }),
        (sessionId) => {
          const result = generateChallenge(sessionId);

          // Structural assertions on the returned challenge
          // (Requirement 2.1, design Property 3).
          if (!(result instanceof Uint8Array)) return false;
          if (result.length !== 32) return false;

          return true;
        },
      ),
      { numRuns: 100 },
    );
  });
});
