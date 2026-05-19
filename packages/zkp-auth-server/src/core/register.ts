/**
 * @zkp-auth/server — framework-agnostic register handler
 *
 * Validates the incoming public key (hex-encoded 32-byte Ed25519 point) and
 * persists it via the caller-supplied `savePublicKey` hook.
 *
 * This function has no Express dependency — the Express adapter in
 * `middleware/register.ts` calls it and maps the result to HTTP.
 */

import { verifyProof, InvalidInputError } from '@zkp-auth/core';
import {
  MissingFieldError,
  InvalidEncodingError,
  InternalError,
  RegistrationFailedError,
  ServerError,
} from '../errors.js';
import type { ZkpRegisterOptions } from '../types.js';

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/** Returned on successful registration. */
export interface RegisterResult {
  /** Always `'registered'` on success. */
  status: 'registered';
  /** The user identifier that was registered. */
  userId: string;
}

// ---------------------------------------------------------------------------
// Security constants / internal option shape
// ---------------------------------------------------------------------------

/**
 * Minimum wall-clock duration for every register attempt. This is a floor, not
 * a hard real-time guarantee; it prevents the obvious fast duplicate-vs-create
 * distinction while the middleware layer adds rate limits and audit logging.
 */
const DEFAULT_MIN_REGISTER_RESPONSE_MS = 150;

type RegisterOptionsWithLookup = ZkpRegisterOptions & {
  /**
   * Required for secure registration. The public type is updated in a later
   * pass; this local shape lets the core fail closed immediately.
   */
  getPublicKey?: (userId: string) => Promise<Uint8Array | null>;
  /**
   * Test/custom-adapter escape hatch for the fixed response-time floor.
   */
  minRegisterResponseMs?: number;
};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Framework-agnostic register handler.
 *
 * Validates the raw body fields and stores the public key. The caller
 * supplies the raw (un-validated) body so this function can produce typed
 * `ServerError`s for every validation failure.
 *
 * The body must contain:
 * - `userId`      — non-empty string.
 * - `publicKeyHex`— 64-character lowercase hex string (32 bytes).
 *
 * @param body    Raw parsed request body (e.g. `req.body`).
 * @param options Middleware options forwarded from the factory.
 * @returns       `RegisterResult` on success.
 * @throws        `ServerError` subclass on any validation failure.
 */
export async function handleRegister(
  body: unknown,
  options: ZkpRegisterOptions,
): Promise<RegisterResult> {
  const startedAt = Date.now();

  try {
    return await handleRegisterInner(body, options);
  } finally {
    await waitForMinimumRegisterDuration(startedAt, options);
  }
}

async function handleRegisterInner(
  body: unknown,
  options: ZkpRegisterOptions,
): Promise<RegisterResult> {
  // ── 1. Parse required fields ──────────────────────────────────────────────
  const { userId, publicKeyHex } = parseBody(body);

  // ── 2. Decode hex → bytes ─────────────────────────────────────────────────
  const publicKey = decodePublicKeyHex(publicKeyHex);

  // ── 3. Validate the key is a legal Ed25519 point by running a dummy
  //       verifyProof call. We pass a dummy challenge (all zeros) and a dummy
  //       proof where s_bytes[32] = 1 (so s = 1n, which is in [1, L) and will
  //       not cause noble's multiply() to throw). verifyProof will:
  //         • throw InvalidInputError('INVALID_PUBLIC_KEY') for a bad/identity key
  //         • return false (never throw) for a valid key with a wrong proof
  //       We only convert INVALID_PUBLIC_KEY into InvalidEncodingError; any
  //       other error propagates as InternalError.
  try {
    const dummyChallenge = new Uint8Array(32);
    // s_bytes must encode a scalar in [1, L). Setting byte 32 to 1 gives s = 1n.
    const dummyProof = new Uint8Array(64);
    dummyProof[32] = 1; // s = 1n — valid scalar, keeps noble happy
    // Return value is false for a valid key (wrong proof) — ignored intentionally.
    verifyProof(publicKey, dummyChallenge, dummyProof);
  } catch (e) {
    if (e instanceof InvalidInputError && e.code === 'INVALID_PUBLIC_KEY') {
      throw new InvalidEncodingError(
        'publicKeyHex',
        `Public key is not a valid Ed25519 point: ${e.message}`,
      );
    }
    // Any other error (e.g. INVALID_CHALLENGE, INVALID_PROOF) is a bug in this
    // function — the dummy inputs are hardcoded to be the right shape.
    throw new InternalError(
      `Unexpected error during public key validation: ${(e as Error).message}`,
    );
  }

  // ── 4. Reject duplicate registration before any write ─────────────────────
  await assertUserIsNotRegistered(userId, options);

  // ── 5. Persist via caller-supplied hook ────────────────────────────────────
  try {
    await options.savePublicKey(userId, publicKey);
  } catch (e) {
    if (e instanceof RegistrationFailedError) {
      throw e;
    }
    throw new InternalError(`savePublicKey threw: ${e instanceof Error ? e.message : String(e)}`);
  }

  return { status: 'registered', userId };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

interface ParsedBody {
  userId: string;
  publicKeyHex: string;
}

/**
 * Extract and coerce `userId` and `publicKeyHex` from an untyped request body.
 *
 * @throws `MissingFieldError` when a required field is absent or not a string.
 */
function parseBody(body: unknown): ParsedBody {
  if (body === null || typeof body !== 'object') {
    throw new MissingFieldError('userId');
  }

  const raw = body as Record<string, unknown>;

  if (typeof raw['userId'] !== 'string' || raw['userId'].length === 0) {
    throw new MissingFieldError('userId');
  }
  if (typeof raw['publicKeyHex'] !== 'string' || raw['publicKeyHex'].length === 0) {
    throw new MissingFieldError('publicKeyHex');
  }

  return {
    userId: raw['userId'],
    publicKeyHex: raw['publicKeyHex'],
  };
}

/**
 * Decode a hex string into a 32-byte `Uint8Array`.
 *
 * @throws `InvalidEncodingError` when the string is not valid 64-char hex.
 */
function decodePublicKeyHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new InvalidEncodingError('publicKeyHex', 'must be exactly 64 hex characters (32 bytes)');
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

/**
 * Fail closed unless the caller exposes a read-before-write hook. Without this
 * check, `savePublicKey` implementations using `set` / `upsert` can overwrite
 * an existing account's authentication key.
 */
async function assertUserIsNotRegistered(
  userId: string,
  options: ZkpRegisterOptions,
): Promise<void> {
  const secureOptions = options as RegisterOptionsWithLookup;
  if (typeof secureOptions.getPublicKey !== 'function') {
    throw new RegistrationFailedError();
  }

  let existing: Uint8Array | null;
  try {
    existing = await secureOptions.getPublicKey(userId);
  } catch (e) {
    throw new InternalError(
      `getPublicKey threw during register: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  if (existing === null) {
    return;
  }

  throw new RegistrationFailedError();
}

async function waitForMinimumRegisterDuration(
  startedAt: number,
  options: ZkpRegisterOptions,
): Promise<void> {
  const configured = (options as RegisterOptionsWithLookup).minRegisterResponseMs;
  const minimumMs =
    typeof configured === 'number' && Number.isFinite(configured) && configured >= 0
      ? configured
      : DEFAULT_MIN_REGISTER_RESPONSE_MS;
  const remainingMs = minimumMs - (Date.now() - startedAt);
  if (remainingMs <= 0) {
    return;
  }
  await new Promise<void>((resolve) => {
    setTimeout(resolve, remainingMs);
  });
}

export { ServerError };
