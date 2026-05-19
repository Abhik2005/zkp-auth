// @zkp-auth/client — typed error classes
//
// Single source of truth for the error taxonomy of `@zkp-auth/client`.
// Every fault path in the SDK throws one of the four concrete subclasses
// declared here, each tagged with a stable `.code` from `ClientErrorCode`.
//
// Design notes:
//
// - `Object.setPrototypeOf(this, new.target.prototype)` is called in every
//   constructor so that `instanceof` works correctly after TypeScript
//   transpiles class syntax to ES5 prototype chains. Without this, a
//   `catch (e)` block that tests `e instanceof ZkpCryptoError` would
//   evaluate to `false` even when the thrown value truly is one.
//
// - The `cause` field follows the ES2022 `Error` options pattern but is
//   assigned via a structural cast so the file compiles under tsconfig
//   `lib: ['ES2022', 'DOM']` regardless of whether the ES2022 error
//   lib typings are present (the same idiom used in @zkp-auth/core).

/**
 * Stable, machine-readable identifiers attached to every error thrown by
 * `@zkp-auth/client`.
 *
 * Callers MUST pattern-match on `.code`; `.message` is for humans only.
 *
 * - `'INVALID_USERNAME'`   — username is empty or exceeds the allowed length.
 * - `'INVALID_PIN'`        — PIN is empty.
 * - `'RNG_FAILURE'`        — `crypto.getRandomValues` threw or the rejection-
 *                            sampling loop exhausted its iteration cap.
 * - `'CURVE_ERROR'`        — `@noble/curves` raised an unexpected internal error.
 * - `'DECRYPTION_FAILED'`  — wrong PIN; AES-GCM authentication tag mismatch.
 * - `'STORAGE_ERROR'`      — IndexedDB read/write failed.
 * - `'KEY_NOT_FOUND'`      — no stored key exists for the given userId.
 * - `'NETWORK_ERROR'`      — `fetch()` itself rejected (offline, CORS, etc.).
 * - `'REGISTER_FAILED'`    — server rejected the registration request.
 * - `'CHALLENGE_FAILED'`   — server did not issue a challenge.
 * - `'PROOF_REJECTED'`     — server's cryptographic verification returned false.
 * - `'SERVER_ERROR'`       — server returned an unexpected status or body.
 */
export type ClientErrorCode =
  | 'INVALID_USERNAME'
  | 'INVALID_PIN'
  | 'RNG_FAILURE'
  | 'CURVE_ERROR'
  | 'DECRYPTION_FAILED'
  | 'STORAGE_ERROR'
  | 'KEY_NOT_FOUND'
  | 'NETWORK_ERROR'
  | 'REGISTER_FAILED'
  | 'CHALLENGE_FAILED'
  | 'PROOF_REJECTED'
  | 'SERVER_ERROR';

/**
 * Base class for all errors thrown by `@zkp-auth/client`.
 *
 * Never thrown directly; always use one of the three concrete subclasses:
 * `ZkpCryptoError`, `ZkpNetworkError`, or `ZkpServerError`.
 */
export class ZkpClientError extends Error {
  /** Fixed class name used as a human-readable discriminator. */
  readonly name: string = 'ZkpClientError';

  /** Stable, machine-readable error code. */
  readonly code: ClientErrorCode;

  constructor(code: ClientErrorCode, message: string) {
    super(message);
    this.code = code;
    // Restore the prototype chain so `instanceof` works after TS transpilation.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when an internal browser-crypto operation fails.
 *
 * Covers five codes:
 *
 * - `'INVALID_USERNAME'`  — the `username` argument is an empty string or
 *   exceeds `MAX_USERNAME_BYTES` (256 UTF-8 bytes).
 * - `'INVALID_PIN'`       — the `pin` argument is an empty string.
 * - `'RNG_FAILURE'`       — `crypto.getRandomValues()` threw, returned a short
 *   buffer, or the rejection-sampling loop exhausted 256 iterations.
 * - `'CURVE_ERROR'`       — `@noble/curves` raised an unexpected error during
 *   a point encode/decode or scalar-multiply operation.
 * - `'DECRYPTION_FAILED'` — AES-GCM authentication tag mismatch; the PIN is
 *   incorrect or the stored ciphertext is corrupt.
 *
 * The underlying error (if any) is attached as `.cause` for diagnostics.
 *
 * @example
 * ```ts
 * try {
 *   await client.login('alice', '000000');
 * } catch (e) {
 *   if (e instanceof ZkpCryptoError && e.code === 'DECRYPTION_FAILED') {
 *     alert('Wrong PIN.');
 *   }
 * }
 * ```
 */
export class ZkpCryptoError extends ZkpClientError {
  override readonly name = 'ZkpCryptoError';

  /**
   * @param code    One of `'INVALID_USERNAME'`, `'INVALID_PIN'`,
   *                `'RNG_FAILURE'`, `'CURVE_ERROR'`, or `'DECRYPTION_FAILED'`.
   * @param message Human-readable description; not part of the stable API.
   * @param options Optional bag; `cause` is the underlying thrown value.
   */
  constructor(
    code: Extract<
      ClientErrorCode,
      'INVALID_USERNAME' | 'INVALID_PIN' | 'RNG_FAILURE' | 'CURVE_ERROR' | 'DECRYPTION_FAILED'
    >,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(code, message);
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

/**
 * Thrown when `fetch()` itself rejects before any HTTP response is received.
 *
 * Typical causes: device offline, DNS failure, CORS preflight rejection,
 * network timeout. The `fetch` rejection reason is attached as `.cause`.
 *
 * `.code` is always `'NETWORK_ERROR'`.
 *
 * @example
 * ```ts
 * if (e instanceof ZkpNetworkError) {
 *   showOfflineBanner();
 * }
 * ```
 */
export class ZkpNetworkError extends ZkpClientError {
  override readonly name = 'ZkpNetworkError';

  /**
   * @param message Human-readable description; not part of the stable API.
   * @param options Optional bag; `cause` is the fetch rejection reason.
   */
  constructor(message: string, options?: { cause?: unknown }) {
    super('NETWORK_ERROR', message);
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

/**
 * Thrown when the server returns a non-success HTTP status, or when the
 * server's JSON response cannot be parsed / does not match the expected
 * `{ error: { code, message } }` envelope.
 *
 * `.httpStatus`  — the HTTP response status code (e.g. 400, 401, 429, 500).
 * `.serverCode`  — the server's own `error.code` string when the response
 *                  body conforms to the server error envelope; `undefined`
 *                  otherwise (malformed JSON, unexpected body shape).
 *
 * `.code` is one of `'REGISTER_FAILED'`, `'CHALLENGE_FAILED'`,
 * `'PROOF_REJECTED'`, or `'SERVER_ERROR'`.
 *
 * @example
 * ```ts
 * if (e instanceof ZkpServerError && e.code === 'PROOF_REJECTED') {
 *   promptReLogin();
 * }
 * if (e instanceof ZkpServerError && e.serverCode === 'RATE_LIMITED') {
 *   scheduleRetry(e.httpStatus); // 429
 * }
 * ```
 */
export class ZkpServerError extends ZkpClientError {
  override readonly name = 'ZkpServerError';

  /** HTTP response status code. */
  readonly httpStatus: number;

  /**
   * The server's `error.code` string when the response body could be parsed
   * and matched the `{ error: { code, message } }` envelope.
   * `undefined` when the body is not JSON or does not match that shape.
   */
  readonly serverCode: string | undefined;

  /**
   * @param code       Client-side error code.
   * @param message    Human-readable description; not part of the stable API.
   * @param httpStatus HTTP response status (e.g. 400, 422, 429, 500).
   * @param serverCode Optional server-supplied `error.code` from the body.
   */
  constructor(
    code: Extract<
      ClientErrorCode,
      'REGISTER_FAILED' | 'CHALLENGE_FAILED' | 'PROOF_REJECTED' | 'SERVER_ERROR'
    >,
    message: string,
    httpStatus: number,
    serverCode?: string,
  ) {
    super(code, message);
    this.httpStatus = httpStatus;
    this.serverCode = serverCode;
  }
}

/**
 * Thrown when a key-storage backend operation fails.
 *
 * Covers two codes:
 *
 * - `'STORAGE_ERROR'`  — IndexedDB (or the active backend) threw an
 *   unexpected error during a read, write, or delete operation.
 * - `'KEY_NOT_FOUND'`  — no stored key exists for the requested `userId`.
 *   The user must register before logging in on this device.
 *
 * @example
 * ```ts
 * try {
 *   await client.login('alice', '123456');
 * } catch (e) {
 *   if (e instanceof ZkpStorageError && e.code === 'KEY_NOT_FOUND') {
 *     redirectToRegister();
 *   }
 * }
 * ```
 */
export class ZkpStorageError extends ZkpClientError {
  override readonly name = 'ZkpStorageError';

  /**
   * @param code    `'STORAGE_ERROR'` or `'KEY_NOT_FOUND'`.
   * @param message Human-readable description; not part of the stable API.
   * @param options Optional bag; `cause` is the underlying thrown value.
   */
  constructor(
    code: Extract<ClientErrorCode, 'STORAGE_ERROR' | 'KEY_NOT_FOUND'>,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(code, message);
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}
