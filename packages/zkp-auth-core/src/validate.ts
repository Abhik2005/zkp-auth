// @zkp-auth/core — input shape validation helpers
//
// All four public functions validate inputs at their entry point. Validation
// is the only place we compute on attacker-supplied data before any
// constant-time considerations apply (length checks are not secret).
//
// Each helper is declared as an `asserts value is Uint8Array` function so the
// TypeScript flow analysis in callers can rely on the narrowed type after
// the call site without an additional cast.
//
// On failure each helper throws `InvalidInputError(code, message)`. Messages
// are human-readable and name the offending `paramName` and the violated
// constraint. Callers MUST pattern-match on `.code` rather than parse
// messages (see Requirement 7.4).
//
// Validates: Requirements 7.1, 7.2, 7.4
// See design.md → "Components and Interfaces" → "validate.ts — Input shape validation".
//
// Implementation note: we deliberately do NOT depend on `@noble/curves`'s
// `abytes` / `ensureBytes` so that the thrown error class is always our
// `InvalidInputError` with a stable `.code`, not noble's internal error
// shape. (design.md, "External API Surface §C".)

import { InvalidInputError, type ErrorCode } from './errors.js';

/**
 * Produces a short, human-readable description of a value's runtime shape,
 * suitable for inclusion in an error message. Never throws; never reveals
 * the value itself (only its kind, to keep secret-bearing inputs out of
 * thrown messages).
 *
 * @param value Arbitrary unknown value.
 * @returns A short kind label such as `"null"`, `"undefined"`, `"string"`,
 *   `"number"`, `"bigint"`, `"boolean"`, `"function"`, `"symbol"`,
 *   `"array"`, or `"object"`.
 */
function describeKind(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

/**
 * Asserts that `value` is a `Uint8Array` instance.
 *
 * `Buffer` extends `Uint8Array`, so callers may pass a `Buffer` and the
 * assertion succeeds — this is intentional. Plain objects with a numeric
 * `.length` property, typed arrays of other element types (e.g.
 * `Uint16Array`), `ArrayBuffer`s, regular arrays, `null`, and `undefined`
 * all fail the check.
 *
 * @param value     Value of unknown shape to validate.
 * @param code      Stable {@link ErrorCode} attached to the thrown error
 *                  so callers can pattern-match on `.code`.
 * @param paramName Name of the parameter being validated, included in the
 *                  human-readable message for diagnostics.
 * @throws InvalidInputError When `value` is not a `Uint8Array` instance.
 */
export function assertUint8Array(
  value: unknown,
  code: ErrorCode,
  paramName: string,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new InvalidInputError(
      code,
      `${paramName} must be a Uint8Array (received ${describeKind(value)})`,
    );
  }
}

/**
 * Asserts that `value` is a `Uint8Array` instance with exactly
 * `expectedLen` bytes.
 *
 * Performs the `Uint8Array` shape check first (delegating to
 * {@link assertUint8Array}) so callers always see the more-specific
 * shape error before any length error.
 *
 * @param value       Value of unknown shape to validate.
 * @param expectedLen Required byte length (exact match).
 * @param code        Stable {@link ErrorCode} attached to the thrown error
 *                    so callers can pattern-match on `.code`.
 * @param paramName   Name of the parameter being validated, included in
 *                    the human-readable message for diagnostics.
 * @throws InvalidInputError When `value` is not a `Uint8Array`, or its
 *   length differs from `expectedLen`.
 */
export function assertUint8ArrayLength(
  value: unknown,
  expectedLen: number,
  code: ErrorCode,
  paramName: string,
): asserts value is Uint8Array {
  assertUint8Array(value, code, paramName);
  if (value.length !== expectedLen) {
    throw new InvalidInputError(
      code,
      `${paramName} must be a Uint8Array of length ${expectedLen} (received length ${value.length})`,
    );
  }
}

/**
 * Asserts that `value` is a `Uint8Array` instance whose length lies in
 * the inclusive range `[minLen, maxLen]`.
 *
 * Performs the `Uint8Array` shape check first (delegating to
 * {@link assertUint8Array}) so callers always see the more-specific
 * shape error before any length error. Both bounds are inclusive — a
 * length equal to `minLen` or `maxLen` is accepted.
 *
 * @param value     Value of unknown shape to validate.
 * @param minLen    Minimum allowed byte length, inclusive.
 * @param maxLen    Maximum allowed byte length, inclusive.
 * @param code      Stable {@link ErrorCode} attached to the thrown error
 *                  so callers can pattern-match on `.code`.
 * @param paramName Name of the parameter being validated, included in the
 *                  human-readable message for diagnostics.
 * @throws InvalidInputError When `value` is not a `Uint8Array`, or its
 *   length falls outside the inclusive `[minLen, maxLen]` range.
 */
export function assertUint8ArrayLengthBetween(
  value: unknown,
  minLen: number,
  maxLen: number,
  code: ErrorCode,
  paramName: string,
): asserts value is Uint8Array {
  assertUint8Array(value, code, paramName);
  if (value.length < minLen || value.length > maxLen) {
    throw new InvalidInputError(
      code,
      `${paramName} must be a Uint8Array of length between ${minLen} and ${maxLen} inclusive (received length ${value.length})`,
    );
  }
}
