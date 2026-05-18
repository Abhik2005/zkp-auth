/**
 * @zkp-auth/server — JWT-specific error class
 *
 * Kept in its own file to avoid circular imports between `jwt.ts` and
 * `errors.ts` (which does not need to know about JWTs).
 */

/**
 * Thrown by `verifyJwt` when the token is structurally invalid, has a
 * bad signature, or has expired.
 */
export class InvalidJwtError extends Error {
  /** Class name; fixed for all instances. */
  readonly name = 'InvalidJwtError';

  /**
   * @param message Human-readable description; not part of the stable API.
   */
  constructor(message: string) {
    super(message);
  }
}
