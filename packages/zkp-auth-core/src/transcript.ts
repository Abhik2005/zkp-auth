// @zkp-auth/core — Fiat-Shamir scalar derivation
//
// This module is the SOLE definition of the Fiat-Shamir hash construction
// used by `@zkp-auth/core`. Both the prover (`compute-proof.ts`) and the
// verifier (`verify-proof.ts`) call into the single function exported here
// — `computeFiatShamirScalar` — so the construction can never drift between
// the two sides. Any change to the transcript is a change in exactly one
// file, gated by the audit guard described below.
//
// The construction is:
//
//   c = int_LE(SHA-512(R_bytes || publicKey_bytes || challenge_bytes)) mod L
//
// where `||` is raw byte concatenation with NO domain separator, NO length
// prefix, and NO padding (Requirement 8.2). The 64-byte SHA-512 digest is
// interpreted as one little-endian integer in `[0, 2^512)` and reduced
// modulo the Ed25519 group order `L`. The resulting scalar `c` is
// statistically indistinguishable from uniform on `[0, L)` (the standard
// "wide-reduction" argument used in EdDSA-family hash-to-scalar
// constructions). We deliberately do NOT truncate the digest to 32 bytes
// before reducing — design "Components and Interfaces → transcript.ts"
// pins the wide-reduction form as the canonical construction so this file
// can be cross-checked against an independent oracle bit-for-bit.
//
// `password` is intentionally absent from the signature, body, and
// imports of this file (Requirements 3.3, 8.1, 11.1). Per Requirement 11
// `password` is reserved-but-unused metadata in v1 and never participates
// in scalar derivation; locking it out at the file level — rather than
// at the call site — makes that contract impossible to violate by
// accident.
//
// This file is the ONLY location under `packages/zkp-auth-core/src/**/*.ts`
// that imports from `@noble/hashes`. The audit guard in task 13.1 enforces
// that invariant by string-matching the import source. Every other module
// that needs `concatBytes` re-imports it from `./encoding.js`, which
// re-exports the symbol exactly so `transcript.ts` and `compute-proof.ts`
// can pull it from a single in-package source.
//
// Validates: Requirements 3.3, 4.3, 8.1, 8.2, 8.3, 8.4, 11.1
// See design.md → "Components and Interfaces" → "transcript.ts".

import { sha512 } from '@noble/hashes/sha512.js';

import { concatBytes, reduceScalar, scalarFromBytesLE } from './encoding.js';

/**
 * Computes the Fiat-Shamir challenge scalar
 * `c = int_LE(SHA-512(R_bytes || publicKey_bytes || challenge_bytes)) mod L`.
 *
 * This is the single point in the codebase where the Fiat-Shamir
 * transcript is defined. `compute-proof.ts` calls it to bind the proof
 * to `(R, publicKey, challenge)`; `verify-proof.ts` calls it with the
 * verbatim same inputs to re-derive the same `c`. Because both sides
 * share this exact function, the construction cannot drift — any change
 * here changes both prover and verifier in lockstep.
 *
 * Algorithm (per design "Components and Interfaces → transcript.ts"):
 *
 *   1. `input = concatBytes(R_bytes, publicKey_bytes, challenge_bytes)`
 *      — 96 bytes; raw concatenation with no separator, no length prefix,
 *      no padding (Requirement 8.2).
 *   2. `digest = sha512(input)` — exactly 64 bytes (Requirement 8.4).
 *   3. `c_unreduced = scalarFromBytesLE(digest)` — interprets the full
 *      64 bytes as one little-endian integer in `[0, 2^512)`. We do NOT
 *      truncate to 32 bytes before reducing; the wide-reduction form is
 *      what makes `c` statistically indistinguishable from uniform on
 *      `[0, L)`, and matches the canonical construction pinned in the
 *      design document.
 *   4. `return reduceScalar(c_unreduced)` — canonical representative in
 *      `[0, L)`.
 *
 * `password` MUST NOT participate in this computation: per Requirement
 * 11.1 it is opaque metadata in v1, and per Requirement 8.1 it is NOT
 * part of the Fiat-Shamir transcript. The function signature is closed
 * over only `(R_bytes, publicKey_bytes, challenge_bytes)` so that no
 * future refactor can quietly add `password` to the hash input.
 *
 * The function performs NO byte-array equality on its inputs; it is a
 * pure hash-and-reduce pipeline. Length validation is the caller's
 * responsibility — `compute-proof.ts` and `verify-proof.ts` validate
 * input shapes via helpers from `validate.ts` before reaching here.
 * Callers always pass exactly 32-byte segments.
 *
 * @param R_bytes         The 32-byte commitment encoding `R = r · G`.
 * @param publicKey_bytes The 32-byte encoding of the prover's public key
 *                        `X = x · G`.
 * @param challenge_bytes The 32-byte verifier-chosen challenge.
 * @returns The Fiat-Shamir challenge scalar `c` as a `bigint` in
 *          `[0, L)`.
 */
export function computeFiatShamirScalar(
  R_bytes: Uint8Array,
  publicKey_bytes: Uint8Array,
  challenge_bytes: Uint8Array,
): bigint {
  const input = concatBytes(R_bytes, publicKey_bytes, challenge_bytes);
  const digest = sha512(input);
  const c_unreduced = scalarFromBytesLE(digest);
  return reduceScalar(c_unreduced);
}
