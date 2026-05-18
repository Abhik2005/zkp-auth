// @zkp-auth/core — single CSPRNG chokepoint
//
// This module is the SOLE call site of `crypto.randomBytes` in
// `packages/zkp-auth-core/src/**/*.ts`. Every public function that needs
// fresh entropy (`generateKeyPair`, `generateChallenge`, `computeProof`)
// funnels through `randomBytes32` so that:
//
//   1. the CSPRNG-failure branch can be audited at a single import site,
//   2. unit tests can mock entropy by mocking exactly this module,
//   3. the audit guard in task 13.1 can verify by string-match that
//      `node:crypto.randomBytes` is imported in exactly one source file.
//
// The wrapper "fails closed" on any RNG anomaly: a throw inside Node's
// CSPRNG, or a buffer of unexpected length, surfaces as `RandomnessError`
// with stable code `'RNG_FAILURE'`. There is no partial-output path, no
// zero-padded fallback, and no silent retry. Callers either receive 32
// fresh bytes or an exception.
//
// Validates: Requirements 1.5, 2.4, 3.10, 6.1
// See design.md → "Components and Interfaces" → "rng.ts — RNG wrapper".

import { randomBytes } from 'node:crypto';

import { RandomnessError } from './errors.js';

/**
 * Returns 32 fresh bytes drawn from the OS CSPRNG.
 *
 * Internally calls `crypto.randomBytes(32)` from `node:crypto` (synchronous
 * overload). The result is normalized to a plain `Uint8Array` — Node's
 * `randomBytes` returns a `Buffer`, which IS a `Uint8Array` subclass, but
 * the public contract of this library narrows the type to `Uint8Array` so
 * downstream consumers do not need to depend on Node's `Buffer` API.
 *
 * The returned array is a fresh copy (via `Uint8Array.from`), detached
 * from Node's internal allocator memory. This matters for callers that
 * zero-fill the buffer after use (see `compute-proof.ts`, Requirement 6.4):
 * mutating the returned array MUST NOT affect any other observer of the
 * original buffer. `Uint8Array.from` is preferred over the equivalent
 * `new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength).slice()`
 * idiom because it is shorter and equally explicit about copying — the
 * single-buffer performance difference is irrelevant at 32 bytes per call.
 *
 * Failure modes — both surface as `RandomnessError` with code
 * `'RNG_FAILURE'`, never as a partial or zero-padded result:
 *
 * - The underlying `randomBytes` call throws (e.g. the OS entropy source
 *   is unavailable). The original error is attached as `.cause`.
 * - The returned buffer has a length other than exactly 32 bytes. This
 *   should never occur with the synchronous overload of `randomBytes`,
 *   but Requirements 1.5, 2.4, and 3.10 explicitly contemplate the
 *   "fewer than 32 bytes" case so we check defensively.
 *
 * @returns A fresh 32-byte `Uint8Array` of CSPRNG output.
 * @throws RandomnessError When the OS CSPRNG throws, or returns a buffer
 *   whose length is not exactly 32 bytes.
 */
export function randomBytes32(): Uint8Array {
  let buf: Buffer;
  try {
    buf = randomBytes(32);
  } catch (e) {
    throw new RandomnessError('CSPRNG failure', { cause: e });
  }
  if (buf.length !== 32) {
    throw new RandomnessError('CSPRNG returned short read');
  }
  return Uint8Array.from(buf);
}
