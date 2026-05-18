// @zkp-auth/core — scalar and point encoding wrappers
//
// This module is the SOLE call site of `@noble/curves`'s scalar and point
// encoding primitives in `packages/zkp-auth-core/src/**/*.ts`. Every
// downstream caller — `keypair.ts`, `compute-proof.ts`, `verify-proof.ts`,
// `transcript.ts` — funnels through these wrappers so that:
//
//   1. the group order `L` is read at module load from
//      `ed25519.Point.Fn.ORDER` and is NEVER hardcoded as a literal — a
//      future `@noble/curves` bump that adjusts the internal field
//      representation continues to work without code change;
//   2. any error raised by `@noble/curves` decoding is re-thrown as
//      `CryptoError` with a stable `.code` and the original error
//      attached as `.cause`, keeping the public error taxonomy closed
//      (Requirement 7.5);
//   3. the verification path can ask for a "soft" parse that returns
//      `null` rather than throwing — required by Requirement 4.7's
//      contract that a malformed `R` MUST cause `verifyProof` to return
//      `false` silently rather than emit an oracle via a thrown error.
//
// `concatBytes` is re-exported from this module so that `transcript.ts`
// and `compute-proof.ts` can `import { concatBytes } from './encoding.js'`
// rather than introducing another `@noble/curves` import site. This keeps
// the audit surface tight: only this file and `transcript.ts` (for
// `sha512` from `@noble/hashes`) need to import directly from the noble
// libraries.
//
// Validates: Requirements 7.5, 8.4 (curve-math source of truth)
// See design.md → "Components and Interfaces" → "encoding.ts" and
// "External API Surface §B–§C".

import { ed25519 } from '@noble/curves/ed25519.js';
import {
  bytesToNumberLE,
  numberToBytesLE,
  concatBytes,
} from '@noble/curves/utils.js';

import { CryptoError } from './errors.js';

/**
 * The runtime shape of a decoded Ed25519 point, as returned by
 * `ed25519.Point.fromBytes`. Exposed so callers can type their locals
 * against the same shape without re-deriving it from `@noble/curves`.
 */
export type EdwardsPoint = ReturnType<typeof ed25519.Point.fromBytes>;

/**
 * The Ed25519 group order
 * `L = 2^252 + 27742317777372353535851937790883648493`.
 *
 * Read at module load from `ed25519.Point.Fn.ORDER`. The literal value
 * is intentionally NOT hardcoded anywhere in this codebase — `L` is the
 * single source of truth for scalar-range checks
 * (`keypair.ts` rejection sampling, `compute-proof.ts` Requirement 3.5,
 * `verify-proof.ts` Requirement 4.8) and for modular reduction
 * (see {@link reduceScalar}). Anchoring on
 * `@noble/curves` honors the "curve math source of truth" rule
 * (Requirement 8.4; design "External API Surface §B").
 */
export const L: bigint = ed25519.Point.Fn.ORDER;

/**
 * The Ed25519 base point (generator) `G`, as defined in RFC 8032 §5.1.
 *
 * Used by every scalar multiplication in the library:
 *
 * - `keypair.ts` computes `publicKey = pointToBytes(BASE.multiply(x))`;
 * - `compute-proof.ts` computes `R = BASE.multiply(r)`;
 * - `verify-proof.ts` computes `lhs = BASE.multiply(s)` for the
 *   verification equation `s · G == R + c · publicKey`.
 *
 * The exposed value is the noble `EdwardsPoint` instance, so callers
 * can invoke the constant-time `multiply` method on it. `multiplyUnsafe`
 * is forbidden anywhere a secret scalar is involved (design "Key design
 * decisions → 4").
 */
export const BASE: EdwardsPoint = ed25519.Point.BASE;

/**
 * Reduces an integer modulo the Ed25519 group order `L`.
 *
 * Delegates to `ed25519.Point.Fn.create(n)`. The result is the canonical
 * representative in `[0, L)`. Callers use this for:
 *
 * - the Fiat-Shamir scalar `c = int_LE(SHA-512(...)) mod L` (see
 *   `transcript.ts`),
 * - the response scalar `s = (r + c · x) mod L` (see `compute-proof.ts`).
 *
 * @param n A `bigint` of any sign or magnitude.
 * @returns `n mod L`, in `[0, L)`.
 */
export function reduceScalar(n: bigint): bigint {
  return ed25519.Point.Fn.create(n);
}

/**
 * Decodes a byte sequence as a non-negative little-endian `bigint`.
 *
 * Performs NO range reduction — the caller decides whether to reduce
 * `mod L`, or whether to reject values outside `[1, L)`. This split is
 * intentional: `keypair.ts` rejects via rejection sampling,
 * `compute-proof.ts` rejects on `>= L` per Requirement 3.5, and
 * `verify-proof.ts` returns `false` on `s >= L` per Requirement 4.8 —
 * three different policies that all share this single decode step.
 *
 * Length is not validated here; callers validate length up-front via
 * helpers from `validate.ts`.
 *
 * @param bytes A `Uint8Array` carrying a little-endian-encoded integer.
 * @returns The non-negative `bigint` decoding of `bytes`.
 */
export function scalarFromBytesLE(bytes: Uint8Array): bigint {
  return bytesToNumberLE(bytes);
}

/**
 * Encodes a non-negative `bigint` as exactly 32 little-endian bytes.
 *
 * Delegates to `numberToBytesLE(n, 32)`. Callers are responsible for
 * ensuring `n` fits in 32 bytes (i.e. `0 <= n < 2^256`); in this
 * library, the only callers feed in scalars already reduced mod `L`
 * via {@link reduceScalar}, so the constraint is satisfied by
 * construction.
 *
 * @param n A non-negative `bigint`, expected to lie in `[0, 2^256)`.
 * @returns A 32-byte `Uint8Array` carrying the little-endian encoding
 *   of `n`.
 */
export function scalarToBytesLE(n: bigint): Uint8Array {
  return numberToBytesLE(n, 32);
}

/**
 * Decodes a 32-byte sequence into an Ed25519 point, throwing on failure.
 *
 * Used by `verify-proof.ts` for the registered `publicKey`: a public
 * key that fails to decode indicates either a misconfigured
 * registration or an integration error, and the contract is to surface
 * a typed error rather than a silent `false`. The caller in
 * `verify-proof.ts` re-wraps the `CryptoError` thrown here as the
 * more-specific `InvalidInputError('INVALID_PUBLIC_KEY', ...)` per
 * Requirement 4.5.
 *
 * Any error raised by `ed25519.Point.fromBytes` — invalid encoding,
 * non-canonical point, off-curve coordinates, etc. — is caught and
 * re-thrown as `new CryptoError('point decoding failed', { cause: e })`,
 * so the original noble error is preserved for diagnostics while the
 * exposed type stays inside the library's stable error taxonomy
 * (Requirement 7.5).
 *
 * @param bytes A 32-byte Ed25519 point encoding (RFC 8032 §5.1.2).
 * @returns The decoded `EdwardsPoint`.
 * @throws CryptoError When `ed25519.Point.fromBytes` rejects the encoding.
 */
export function pointFromBytesStrict(bytes: Uint8Array): EdwardsPoint {
  try {
    return ed25519.Point.fromBytes(bytes);
  } catch (e: unknown) {
    throw new CryptoError('point decoding failed', { cause: e });
  }
}

/**
 * Decodes a 32-byte sequence into an Ed25519 point, returning `null`
 * on failure instead of throwing.
 *
 * Used by `verify-proof.ts` exclusively for the `R` component of an
 * incoming `proof`. Per Requirement 4.7, a malformed `R` MUST cause
 * `verifyProof` to return `false` silently — throwing would expose an
 * oracle distinguishing "malformed `R`" from "well-formed but invalid
 * proof". Returning `null` lets the caller convert the failure into a
 * boolean return without ever materializing an exception.
 *
 * Any error raised by `ed25519.Point.fromBytes` is swallowed; the
 * underlying noble error is intentionally not surfaced here, as this
 * code path is the one place the library is designed to be silent.
 *
 * @param bytes A 32-byte sequence to decode.
 * @returns The decoded `EdwardsPoint`, or `null` if
 *   `ed25519.Point.fromBytes` rejected the encoding for any reason.
 */
export function pointFromBytesSoft(bytes: Uint8Array): EdwardsPoint | null {
  try {
    return ed25519.Point.fromBytes(bytes);
  } catch {
    return null;
  }
}

/**
 * Encodes an Ed25519 point as 32 bytes per RFC 8032 §5.1.2.
 *
 * Delegates to the instance method `p.toBytes()`. The deprecated
 * `p.toRawBytes()` is intentionally NOT used (External API Surface §B).
 *
 * @param p An `EdwardsPoint` produced by curve math or by one of the
 *   decoding helpers in this module.
 * @returns The 32-byte canonical encoding of `p`.
 */
export function pointToBytes(p: EdwardsPoint): Uint8Array {
  return p.toBytes();
}

/**
 * Concatenates an arbitrary number of `Uint8Array` segments into a single
 * `Uint8Array`. Re-exported from `@noble/curves/utils.js`.
 *
 * Surfaced here so that `transcript.ts` and `compute-proof.ts` can
 * import `concatBytes` from `./encoding.js` rather than adding another
 * direct `@noble/curves` import site. Keeping the noble import surface
 * narrow makes the audit guard in task 13.1 a single-file string-match.
 */
export { concatBytes };
