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

  // ── 4. Persist via caller-supplied hook ────────────────────────────────────
  try {
    await options.savePublicKey(userId, publicKey);
  } catch (e) {
    throw new InternalError(
      `savePublicKey threw: ${e instanceof Error ? e.message : String(e)}`,
    );
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
    throw new InvalidEncodingError(
      'publicKeyHex',
      'must be exactly 64 hex characters (32 bytes)',
    );
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

export { ServerError };
