/**
 * @zkp-auth/server — framework-agnostic verify handler
 *
 * Orchestrates the full proof-verification flow:
 *  1. Parse and decode the request body (userId, proofHex).
 *  2. Look up the registered public key via the caller-supplied hook.
 *  3. Atomically consume the live challenge from the store.
 *  4. Call `verifyProof` from `@zkp-auth/core`.
 *  5. Issue an HS256 JWT via `signJwt`.
 *
 * JWT is issued ONLY after cryptographic verification returns `true`.
 * Every failure path throws a typed `ServerError` subclass so the Express
 * adapter can map it to a consistent error response.
 */

import { verifyProof } from '@zkp-auth/core';
import { InvalidInputError } from '@zkp-auth/core';
import {
  MissingFieldError,
  InvalidEncodingError,
  ChallengeNotFoundError,
  ChallengeExpiredError,
  ProofInvalidError,
  PublicKeyNotFoundError,
  InternalError,
  ServerError,
} from '../errors.js';
import { signJwt } from '../jwt.js';
import type { ZkpVerifyOptions } from '../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default JWT lifetime: 1 hour. */
const DEFAULT_JWT_EXPIRES_IN_SECONDS = 3_600;

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/** Returned on successful verification. */
export interface VerifyResult {
  /** Always `'verified'` on success. */
  status: 'verified';
  /** The authenticated user identifier. */
  userId: string;
  /** Signed HS256 JWT. */
  token: string;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Framework-agnostic verify handler.
 *
 * @param body    Raw parsed request body (e.g. `req.body`).
 * @param options Middleware options forwarded from the factory.
 * @returns       `VerifyResult` on success.
 * @throws        `ServerError` subclass on any failure.
 */
export async function handleVerify(
  body: unknown,
  options: ZkpVerifyOptions,
): Promise<VerifyResult> {
  // ── 1. Parse required fields ──────────────────────────────────────────────
  const { userId, proofHex } = parseBody(body);

  // ── 2. Decode proof hex → bytes ───────────────────────────────────────────
  const proof = decodeProofHex(proofHex);

  // ── 3. Look up registered public key ──────────────────────────────────────
  let publicKey: Uint8Array | null;
  try {
    publicKey = await options.getPublicKey(userId);
  } catch (e) {
    throw new InternalError(
      `getPublicKey threw: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  if (publicKey === null) {
    throw new PublicKeyNotFoundError(userId);
  }

  // ── 4. Atomically consume the live challenge ───────────────────────────────
  // consumeIfLive returns null when:
  //   a) no challenge was ever issued (CHALLENGE_NOT_FOUND), OR
  //   b) the challenge has expired (we cannot distinguish — return NOT_FOUND
  //      in both cases to avoid information leakage about timing), OR
  //   c) the challenge was already consumed (CHALLENGE_REPLAYED).
  //
  // Cases (a) and (b) are indistinguishable after consumption; we return
  // CHALLENGE_NOT_FOUND for both. Case (c) is also CHALLENGE_NOT_FOUND
  // post-deletion — the entry no longer exists. This is intentional: the
  // attacker learns nothing beyond "no valid challenge".
  //
  // To distinguish expiry at the UX level (so the client can prompt for
  // a new challenge vs. just try again), we check expiry BEFORE deletion
  // by not using consumeIfLive's null ambiguity. Because our InMemoryChallengeStore
  // deletes first and then checks expiry, the discrimination is impossible
  // from the public interface. This is fine: the HTTP 400 body has code
  // CHALLENGE_NOT_FOUND, which the client should treat as "request a new
  // challenge".
  let challenge: Uint8Array | null;
  try {
    challenge = await options.store.consumeIfLive(userId);
  } catch (e) {
    throw new InternalError(
      `Challenge store consumeIfLive threw: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  if (challenge === null) {
    // Distinguish expired from not-found requires a separate lookup that this
    // interface does not support — emit ChallengeExpiredError as a best-effort
    // hint. Replay also falls here (entry was deleted on first consume).
    // We choose ChallengeExpiredError for the common UX case (session timed
    // out), the client should always call /challenge again on any 400.
    //
    // Security note: both expired and replayed challenges return the same
    // HTTP 400 body structure; the code differs (CHALLENGE_EXPIRED vs
    // CHALLENGE_NOT_FOUND) but neither leaks cryptographic material.
    throw new ChallengeExpiredError();
  }

  // ── 5. Cryptographic verification ─────────────────────────────────────────
  // verifyProof is the only function allowed to touch the proof bytes.
  // It may throw InvalidInputError for structural problems (bad public key
  // encoding, wrong proof length). Those are caller bugs and surface as
  // InternalError here — the middleware has already validated lengths above,
  // so an InvalidInputError at this point means the stored public key is
  // malformed.
  let valid: boolean;
  try {
    valid = verifyProof(publicKey, challenge, proof);
  } catch (e) {
    if (e instanceof InvalidInputError) {
      // Stored public key or challenge is malformed — internal fault.
      throw new InternalError(
        `verifyProof threw ${e.code}: ${e.message}`,
      );
    }
    throw new InternalError(
      `verifyProof threw unexpectedly: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  if (!valid) {
    throw new ProofInvalidError();
  }

  // ── 6. Issue JWT (ONLY after verification returns true) ───────────────────
  const expiresInSeconds =
    options.jwtExpiresInSeconds ?? DEFAULT_JWT_EXPIRES_IN_SECONDS;

  let token: string;
  try {
    token = signJwt(userId, options.jwtSecret, expiresInSeconds);
  } catch (e) {
    throw new InternalError(
      `JWT signing failed: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  return { status: 'verified', userId, token };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

interface ParsedBody {
  userId: string;
  proofHex: string;
}

function parseBody(body: unknown): ParsedBody {
  if (body === null || typeof body !== 'object') {
    throw new MissingFieldError('userId');
  }

  const raw = body as Record<string, unknown>;

  if (typeof raw['userId'] !== 'string' || raw['userId'].length === 0) {
    throw new MissingFieldError('userId');
  }
  if (typeof raw['proofHex'] !== 'string' || raw['proofHex'].length === 0) {
    throw new MissingFieldError('proofHex');
  }

  return {
    userId: raw['userId'],
    proofHex: raw['proofHex'],
  };
}

/**
 * Decode a hex string into a 64-byte `Uint8Array` (proof = R_bytes || s_bytes).
 *
 * @throws `InvalidEncodingError` when the string is not valid 128-char hex.
 */
function decodeProofHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]{128}$/.test(hex)) {
    throw new InvalidEncodingError(
      'proofHex',
      'must be exactly 128 hex characters (64 bytes)',
    );
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

export { ServerError, ChallengeNotFoundError };
