/**
 * @zkp-auth/server — typed error classes
 *
 * All errors thrown by the middleware are instances of one of these
 * classes. HTTP responses produced by the adapters always serialise
 * errors as `{ error: { code, message } }` — callers must never
 * rely on `.message` for programmatic matching; use `.code` only.
 */

// ---------------------------------------------------------------------------
// Error code discriminator
// ---------------------------------------------------------------------------

/**
 * Stable, machine-readable identifiers for every middleware fault path.
 *
 * - `MISSING_FIELD`       — a required request field (body/header) is absent.
 * - `INVALID_ENCODING`    — a field cannot be decoded from its expected format.
 * - `CHALLENGE_NOT_FOUND` — no live challenge exists for the given session.
 * - `CHALLENGE_EXPIRED`   — challenge was found but its TTL has elapsed.
 * - `CHALLENGE_REPLAYED`  — the same challenge was submitted more than once.
 * - `PROOF_INVALID`       — cryptographic verification returned false.
 * - `PUBLIC_KEY_NOT_FOUND`— the user's public key is not registered.
 * - `RATE_LIMITED`        — the external rate-limiter hook rejected the request.
 * - `INTERNAL_ERROR`      — unexpected internal fault (wraps crypto / IO errors).
 */
export type ServerErrorCode =
  | 'MISSING_FIELD'
  | 'INVALID_ENCODING'
  | 'CHALLENGE_NOT_FOUND'
  | 'CHALLENGE_EXPIRED'
  | 'CHALLENGE_REPLAYED'
  | 'PROOF_INVALID'
  | 'PUBLIC_KEY_NOT_FOUND'
  | 'RATE_LIMITED'
  | 'INTERNAL_ERROR';

// ---------------------------------------------------------------------------
// Error class
// ---------------------------------------------------------------------------

/**
 * Every middleware error extends `ServerError`. The `.code` field is the
 * stable discriminator; `.message` is for logs/humans only.
 *
 * The `.httpStatus` is a suggestion; the Express adapters use it to set
 * `res.status(...)`. Framework-agnostic callers may inspect it directly.
 */
export class ServerError extends Error {
  /** Class name; fixed for all instances. */
  readonly name = 'ServerError';
  /** Stable, machine-readable identifier for the failure. */
  readonly code: ServerErrorCode;
  /** HTTP status code to use when serialising this error. */
  readonly httpStatus: number;

  /**
   * @param code       Stable error identifier.
   * @param message    Human-readable description; not part of the stable API.
   * @param httpStatus HTTP status to use in responses. Default: 400.
   */
  constructor(code: ServerErrorCode, message: string, httpStatus = 400) {
    super(message);
    this.code = code;
    this.httpStatus = httpStatus;
  }
}

// ---------------------------------------------------------------------------
// Named subclasses for common fault paths (mirrors core's error taxonomy)
// ---------------------------------------------------------------------------

/** The body is missing a required field. */
export class MissingFieldError extends ServerError {
  constructor(field: string) {
    super('MISSING_FIELD', `Missing required field: ${field}`, 400);
  }
}

/** A field cannot be decoded from its expected format (e.g. bad hex). */
export class InvalidEncodingError extends ServerError {
  constructor(field: string, detail?: string) {
    super(
      'INVALID_ENCODING',
      detail !== undefined
        ? `Invalid encoding for field '${field}': ${detail}`
        : `Invalid encoding for field '${field}'`,
      400,
    );
  }
}

/** No live challenge found for the given session. */
export class ChallengeNotFoundError extends ServerError {
  constructor() {
    super('CHALLENGE_NOT_FOUND', 'No active challenge for this session', 400);
  }
}

/** Challenge TTL has elapsed. */
export class ChallengeExpiredError extends ServerError {
  constructor() {
    super('CHALLENGE_EXPIRED', 'Challenge has expired', 400);
  }
}

/** The same challenge has already been consumed. */
export class ChallengeReplayedError extends ServerError {
  constructor() {
    super('CHALLENGE_REPLAYED', 'Challenge has already been used', 400);
  }
}

/** Cryptographic proof verification returned false. */
export class ProofInvalidError extends ServerError {
  constructor() {
    super('PROOF_INVALID', 'Proof verification failed', 401);
  }
}

/** No public key is registered for this user. */
export class PublicKeyNotFoundError extends ServerError {
  constructor(userId: string) {
    super('PUBLIC_KEY_NOT_FOUND', `No public key registered for user '${userId}'`, 401);
  }
}

/** The external rate-limiter hook rejected the request. */
export class RateLimitedError extends ServerError {
  constructor() {
    super('RATE_LIMITED', 'Too many requests', 429);
  }
}

/** Unexpected internal error. */
export class InternalError extends ServerError {
  constructor(detail?: string) {
    super(
      'INTERNAL_ERROR',
      detail !== undefined ? `Internal error: ${detail}` : 'Internal error',
      500,
    );
  }
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/** JSON shape returned by all error responses. */
export interface ErrorResponseBody {
  error: {
    code: ServerErrorCode;
    message: string;
  };
}

/**
 * Serialise a `ServerError` into the canonical wire format.
 *
 * @param err Any `ServerError` (or subclass) instance.
 * @returns   The JSON-serialisable error envelope.
 */
export function toErrorBody(err: ServerError): ErrorResponseBody {
  return { error: { code: err.code, message: err.message } };
}
