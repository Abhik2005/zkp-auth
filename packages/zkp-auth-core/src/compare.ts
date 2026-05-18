// @zkp-auth/core — constant-time byte equality
//
// This module is the SOLE call site of `crypto.timingSafeEqual` in
// `packages/zkp-auth-core/src/**/*.ts`. Every byte-array equality over
// secret or attacker-chosen data in the library funnels through
// `timingSafeEqualBytes` so that side-channel discipline can be audited
// statically (audit task 13.1 enforces this with a string-match guard).
//
// Validates: Requirements 5.1, 5.2, 5.3, 5.4
// See design.md → "Components and Interfaces" → "compare.ts — Constant-time byte equality".

import { timingSafeEqual } from 'node:crypto';

/**
 * Constant-time byte-array equality with length tolerance.
 *
 * Wraps Node's `crypto.timingSafeEqual` to provide two guarantees on top of
 * the underlying primitive:
 *
 * 1. If `a.length !== b.length`, returns `false` without throwing.
 *    Node's `crypto.timingSafeEqual` throws `RangeError` on unequal-length
 *    inputs; that throw would itself be a side channel and would force every
 *    caller to wrap the call in `try`/`catch`. Length is public information
 *    in this protocol (it is part of the encoding contract), so a synchronous
 *    `false` return is safe and ergonomic.
 * 2. Otherwise delegates to `crypto.timingSafeEqual`, which performs a
 *    constant-time comparison over the two equal-length buffers.
 *
 * This is the ONLY function in every TypeScript file under src/ allowed
 * to compare bytes derived from a private key, nonce, password, proof, or
 * challenge. Callers that need byte equality on secret or attacker-chosen
 * data MUST route through this helper; direct use of `===`, `==`,
 * `Buffer.equals`, or `Uint8Array`-iterating short-circuit comparisons is
 * forbidden by the library's audit guard.
 *
 * @param a First byte array.
 * @param b Second byte array.
 * @returns `true` iff `a` and `b` have the same length and every byte
 *          matches; `false` otherwise. Never throws.
 */
export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}
