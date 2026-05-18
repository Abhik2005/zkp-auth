// @zkp-auth/core — typed error classes
//
// This module is the single source of truth for the error taxonomy of
// `@zkp-auth/core`. Every fault path in the library throws one of the three
// classes declared here, each tagged with a stable `.code` from `ErrorCode`
// so callers can pattern-match on `.code` instead of parsing messages.
//
// Validates: Requirements 7.1, 7.2, 7.4, 7.5
// See design.md → "Components and Interfaces" → "errors.ts — Typed error classes".

/**
 * Stable, machine-readable identifiers attached to every thrown error.
 *
 * Callers are expected to pattern-match on `.code` rather than inspect
 * `.message`, which is for human readers only. The set is closed: adding a
 * new code is a breaking change to the public API surface.
 *
 * - `INVALID_PRIVATE_KEY` — privateKey shape, length, or scalar range invalid.
 * - `INVALID_PUBLIC_KEY`  — publicKey shape, length, decode, or identity-point.
 * - `INVALID_CHALLENGE`   — challenge shape or length invalid.
 * - `INVALID_PROOF`       — proof shape or length invalid (NOT verification failure).
 * - `INVALID_PASSWORD`    — password shape or length invalid.
 * - `INVALID_SESSION_ID`  — sessionId shape, empty, or oversize.
 * - `RNG_FAILURE`         — CSPRNG threw, returned short, or rejection-sampling exhausted.
 * - `CURVE_ERROR`         — `@noble/curves` raised an unexpected internal error.
 */
export type ErrorCode =
  | 'INVALID_PRIVATE_KEY'
  | 'INVALID_PUBLIC_KEY'
  | 'INVALID_CHALLENGE'
  | 'INVALID_PROOF'
  | 'INVALID_PASSWORD'
  | 'INVALID_SESSION_ID'
  | 'RNG_FAILURE'
  | 'CURVE_ERROR';

/**
 * Thrown when a public function receives an input that fails shape, length,
 * encoding, or range validation. The accompanying `.code` indicates which
 * input was invalid.
 *
 * `.name` is set as a readonly class field so it cannot be silently shadowed
 * by user-land subclasses or by `Error`'s default `'Error'` value.
 *
 * @example
 * try {
 *   computeProof(privateKey, password, challenge);
 * } catch (e) {
 *   if (e instanceof InvalidInputError && e.code === 'INVALID_CHALLENGE') {
 *     // handle challenge-shape failure
 *   }
 * }
 */
export class InvalidInputError extends Error {
  /** Class name; fixed for all instances. */
  readonly name = 'InvalidInputError';
  /** Stable, machine-readable identifier for the failing input. */
  readonly code: ErrorCode;

  /**
   * @param code    Stable identifier for the failing input.
   * @param message Human-readable description; not part of the stable API.
   */
  constructor(code: ErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

/**
 * Thrown when the underlying CSPRNG throws, returns a short read, or when
 * bounded rejection sampling exhausts its iteration cap (treated as an RNG
 * anomaly). The library MUST NOT emit a partial output on this failure path.
 *
 * `.code` is fixed to `'RNG_FAILURE'`. The optional `cause` carries the
 * underlying error (e.g. the `node:crypto.randomBytes` throw) for diagnostics.
 *
 * `cause` is attached via a structural cast so the assignment works under
 * any tsconfig `lib` selection that may or may not include
 * `lib.es2022.error.d.ts` (per design.md).
 */
export class RandomnessError extends Error {
  /** Class name; fixed for all instances. */
  readonly name = 'RandomnessError';
  /** Stable, machine-readable identifier; fixed for this class. */
  readonly code: ErrorCode = 'RNG_FAILURE';

  /**
   * @param message Human-readable description; not part of the stable API.
   * @param options Optional bag carrying the underlying `cause`.
   */
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

/**
 * Thrown when an internal `@noble/curves` operation raises an unexpected
 * error (e.g. invalid point encoding) on a code path where the library's
 * contract is to throw rather than return `false`. The verification path's
 * silent-`false` returns for malformed `R` and out-of-range `s` are
 * deliberate exceptions to this rule (see design.md, Requirements 4.7, 4.8).
 *
 * `.code` is fixed to `'CURVE_ERROR'`. The optional `cause` carries the
 * underlying noble error for diagnostics.
 */
export class CryptoError extends Error {
  /** Class name; fixed for all instances. */
  readonly name = 'CryptoError';
  /** Stable, machine-readable identifier; fixed for this class. */
  readonly code: ErrorCode = 'CURVE_ERROR';

  /**
   * @param message Human-readable description; not part of the stable API.
   * @param options Optional bag carrying the underlying `cause`.
   */
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}
