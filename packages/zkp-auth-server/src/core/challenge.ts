/**
 * @zkp-auth/server — framework-agnostic challenge handler
 *
 * Generates a fresh 32-byte challenge via `generateChallenge` from
 * `@zkp-auth/core`, stores it in the `IChallengeStore`, and returns the
 * challenge as a hex string for the client to include in its proof.
 *
 * The session ID used as the store key is the userId — this binds one
 * live challenge per user at a time (hitting /challenge twice gives only
 * the second challenge).
 */

import { generateChallenge } from '@zkp-auth/core';
import { MissingFieldError, InternalError, ServerError } from '../errors.js';
import type { ZkpChallengeOptions } from '../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default challenge TTL: 60 seconds. */
const DEFAULT_TTL_MS = 60_000;

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/** Returned on successful challenge issuance. */
export interface ChallengeResult {
  /** Always `'challenge_issued'` on success. */
  status: 'challenge_issued';
  /** Hex-encoded 32-byte challenge. The client MUST include this in the proof. */
  challengeHex: string;
  /** Challenge TTL in milliseconds (informational; not enforced client-side). */
  expiresInMs: number;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Framework-agnostic challenge handler.
 *
 * @param body    Raw parsed request body (e.g. `req.body`).
 * @param options Middleware options forwarded from the factory.
 * @returns       `ChallengeResult` on success.
 * @throws        `ServerError` subclass on any validation / storage failure.
 */
export async function handleChallenge(
  body: unknown,
  options: ZkpChallengeOptions,
): Promise<ChallengeResult> {
  // ── 1. Parse required fields ──────────────────────────────────────────────
  const { userId } = parseBody(body);

  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;

  // ── 2. Generate challenge via core ────────────────────────────────────────
  // The sessionId passed to generateChallenge is a Uint8Array — we encode the
  // userId as UTF-8. generateChallenge validates the length (1–256 bytes) and
  // then returns 32 CSPRNG bytes that are independent of the sessionId.
  let challenge: Uint8Array;
  try {
    const sessionIdBytes = new TextEncoder().encode(userId);
    if (sessionIdBytes.length === 0 || sessionIdBytes.length > 256) {
      throw new MissingFieldError('userId');
    }
    challenge = generateChallenge(sessionIdBytes);
  } catch (e) {
    if (e instanceof ServerError) throw e;
    // Core throws InvalidInputError or RandomnessError — surface as internal.
    throw new InternalError(
      `generateChallenge failed: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  // ── 3. Persist in store ───────────────────────────────────────────────────
  try {
    await options.store.set(userId, challenge, ttlMs);
  } catch (e) {
    throw new InternalError(
      `Challenge store set failed: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  return {
    status: 'challenge_issued',
    challengeHex: Buffer.from(challenge).toString('hex'),
    expiresInMs: ttlMs,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

interface ParsedBody {
  userId: string;
}

function parseBody(body: unknown): ParsedBody {
  if (body === null || typeof body !== 'object') {
    throw new MissingFieldError('userId');
  }

  const raw = body as Record<string, unknown>;

  if (typeof raw['userId'] !== 'string' || raw['userId'].length === 0) {
    throw new MissingFieldError('userId');
  }

  return { userId: raw['userId'] };
}

export { ServerError };
