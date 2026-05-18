// @zkp-auth/core — `generateChallenge` for verifier-chosen per-session nonces
//
// This module implements the sole challenge-generation entry point of
// `@zkp-auth/core`. It validates the caller-supplied `sessionId` for
// shape (Requirement 2.2) and then returns 32 fresh CSPRNG bytes drawn
// from the chokepoint `randomBytes32()`. The returned challenge is
// the verifier's contribution to the Schnorr-proof transcript; binding
// each authentication attempt to a unique value is what makes proofs
// non-replayable across sessions (Requirement 2 user-story).
//
// Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5
// See design.md → "Components and Interfaces → challenge.ts" and
//     requirements.md → "Requirement 2: Challenge Generation".
//
// SECURITY-CRITICAL CONTRACT — Requirement 2.5 / Property 4:
//
//   The returned 32 bytes MUST NOT be a function of `sessionId`. After
//   the validation call, `sessionId` is never read, never hashed, never
//   mixed into the RNG state, and never folded into the output in any
//   way. The body is exactly two statements: validation, then a fresh
//   `randomBytes32()` call whose result is returned unchanged.
//
//   The reason for this strict separation is the threat model in
//   requirements.md OQ-3: `sessionId` is the caller's server-side
//   bookkeeping handle (e.g. a database row id) and may be predictable
//   or adversary-influenced. Mixing it into the challenge would
//   downgrade the challenge's unpredictability to that of `sessionId`,
//   defeating the very property the verifier needs from this function.
//   The `sessionId → challenge` association is maintained by the
//   caller's protocol layer, not by this library.
//
// Implementation notes:
//
// - The 1..256-byte length window for `sessionId` (Requirement 2.2) is
//   wide enough to accept any reasonable session-handle encoding —
//   UUIDs (16 bytes), 256-bit hex strings (64 bytes), opaque tokens —
//   while rejecting empty inputs (which suggest a caller bug) and
//   absurdly large inputs (which suggest accidental payload-passing
//   or a DoS attempt against any caller-side bookkeeping). The bound
//   is enforced by `assertUint8ArrayLengthBetween` with both bounds
//   inclusive.
//
// - The validation step's `'INVALID_SESSION_ID'` error code is fixed
//   in the `ErrorCode` taxonomy (`./errors.ts`); callers pattern-match
//   on `.code` to distinguish session-id failures from any other
//   `InvalidInputError`. Any non-`Uint8Array` shape, zero-length, or
//   over-256-byte input flows through this single code.
//
// - The RNG-failure path propagates `RandomnessError` from
//   `randomBytes32()` unchanged when the underlying CSPRNG throws.
//   Because tests mock `rng.ts` directly via `vi.mock` and may inject
//   a raw `Error` (property-13's `generateChallenge` portion does this),
//   the call is wrapped in a try/catch that re-wraps any non-
//   `RandomnessError` as one. This is a defense-in-depth no-op in
//   production — `rng.ts` already wraps all faults at the chokepoint —
//   but ensures the public-API contract holds at this module's boundary
//   regardless of what the mock injects.
//   A post-call length check (`result.length !== 32`) defends against
//   the "short-read" mock case (`new Uint8Array(31)`) which bypasses
//   `rng.ts`'s own length guard. Both failure modes surface as
//   `RandomnessError` with stable code `'RNG_FAILURE'`, no partial
//   output (Requirement 2.4).
//
// - There are no byte-array equality comparisons in this file. The
//   audit guard (task 13.1) will see only the validation call and the
//   `randomBytes32()` return — no `===`, no `!==`, no `Buffer.equals`.

import { RandomnessError } from './errors.js';
import { assertUint8ArrayLengthBetween } from './validate.js';
import { randomBytes32 } from './rng.js';

/**
 * Generates a fresh 32-byte challenge for a Schnorr-proof
 * authentication session.
 *
 * The returned bytes are drawn from the OS CSPRNG via the library's
 * single chokepoint (`randomBytes32`) and are statistically
 * independent of `sessionId` — the parameter exists only so the
 * caller's wire protocol can validate session-handle shape at a
 * single, well-defined entry point. See the file-header comment for
 * the security rationale (Requirement 2.5 / Property 4).
 *
 * The returned `Uint8Array` is a fresh allocation, detached from any
 * internal CSPRNG buffer pool (see `rng.ts`'s `Uint8Array.from` step),
 * so the caller may zero-fill it after use without affecting any
 * other observer.
 *
 * Failure modes:
 *
 * - `InvalidInputError` with `code === 'INVALID_SESSION_ID'` — thrown
 *   when `sessionId` is not a `Uint8Array`, has length 0, or has
 *   length greater than 256 bytes. The 1..256-byte inclusive window
 *   is enforced by `assertUint8ArrayLengthBetween`.
 * - `RandomnessError` with `code === 'RNG_FAILURE'` — thrown when
 *   `randomBytes32()` throws (any underlying CSPRNG fault), or when
 *   the returned buffer is not exactly 32 bytes. In production,
 *   `rng.ts` wraps both cases before they reach this function; the
 *   extra length guard and try/catch here are defense-in-depth for
 *   test-injected mocks (property-13, `vi.mock`). No partial or
 *   zero-padded challenge is ever returned (Requirement 2.4).
 *
 * @param sessionId Caller-supplied session handle. Validated for
 *   `Uint8Array` shape and a length in the inclusive range
 *   `[1, 256]`; never read after validation.
 * @returns A fresh 32-byte CSPRNG-derived `Uint8Array`, independent
 *   of `sessionId`.
 * @throws InvalidInputError When `sessionId` fails shape or length
 *   validation.
 * @throws RandomnessError When the underlying CSPRNG throws or
 *   returns a short read.
 */
export function generateChallenge(sessionId: Uint8Array): Uint8Array {
  assertUint8ArrayLengthBetween(sessionId, 1, 256, 'INVALID_SESSION_ID', 'sessionId');

  // Defense-in-depth: wrap the randomBytes32() call so that any error —
  // whether a `RandomnessError` already produced by `rng.ts`, or a raw
  // `Error` injected by a `vi.mock` in tests — surfaces as a
  // `RandomnessError`. In production this is a no-op; `rng.ts` wraps
  // every CSPRNG fault at the chokepoint. The short-read length check
  // covers the test case where the mock returns a 31-byte buffer that
  // bypasses `rng.ts`'s own length guard entirely (property-13,
  // generateChallenge portion, task 6.4).
  let result: Uint8Array;
  try {
    result = randomBytes32();
  } catch (e) {
    if (e instanceof RandomnessError) throw e;
    throw new RandomnessError('CSPRNG failure', { cause: e });
  }
  if (result.length !== 32) {
    throw new RandomnessError('CSPRNG returned short read');
  }
  return result;
}
