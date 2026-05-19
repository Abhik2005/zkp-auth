/**
 * @zkp-auth/server — authenticated public-key rotation.
 *
 * Rekey is intentionally separate from registration. A caller must prove
 * knowledge of the current private key against the current registered public
 * key before `savePublicKey` receives the replacement key.
 */

import type { RequestHandler } from 'express';
import { verifyProof, InvalidInputError } from '@zkp-auth/core';
import {
  MissingFieldError,
  InvalidEncodingError,
  ChallengeExpiredError,
  ProofInvalidError,
  PublicKeyNotFoundError,
  InternalError,
  ServerError,
  RateLimitedError,
  toErrorBody,
} from './errors.js';
import { logKeyOverwriteAttempt } from './audit-log.js';
import { enforceAuthRateLimit, getRequestIp } from './rate-limit.js';
import type { GetPublicKeyFn, IChallengeStore, SavePublicKeyFn } from './types.js';
import type { AuditLogger } from './audit-log.js';
import type { InMemoryRateLimiter } from './rate-limit.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

const DEFAULT_MIN_REKEY_RESPONSE_MS = 150;

export interface ZkpRekeyOptions {
  readonly getPublicKey: GetPublicKeyFn;
  readonly savePublicKey: SavePublicKeyFn;
  readonly store: IChallengeStore;
  readonly minRekeyResponseMs?: number;
  readonly authRateLimiter?: InMemoryRateLimiter | false;
  readonly auditLogger?: AuditLogger;
  readonly rateLimitHook?: (req: Parameters<RequestHandler>[0]) => Promise<void>;
}

export interface RekeyResult {
  readonly status: 'rekeyed';
  readonly userId: string;
}

interface ParsedBody {
  readonly userId: string;
  readonly proofHex: string;
  readonly newPublicKeyHex: string;
}

// ---------------------------------------------------------------------------
// Framework-agnostic handler
// ---------------------------------------------------------------------------

export async function handleRekey(body: unknown, options: ZkpRekeyOptions): Promise<RekeyResult> {
  const startedAt = Date.now();
  try {
    return await handleRekeyInner(body, options);
  } finally {
    await waitForMinimumRekeyDuration(startedAt, options);
  }
}

async function handleRekeyInner(body: unknown, options: ZkpRekeyOptions): Promise<RekeyResult> {
  const { userId, proofHex, newPublicKeyHex } = parseBody(body);

  const proof = decodeProofHex(proofHex);
  const newPublicKey = decodePublicKeyHex(newPublicKeyHex);
  validatePublicKey(newPublicKey, 'newPublicKeyHex');

  let currentPublicKey: Uint8Array | null;
  try {
    currentPublicKey = await options.getPublicKey(userId);
  } catch (e) {
    throw new InternalError(
      `getPublicKey threw during rekey: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  if (currentPublicKey === null) {
    throw new PublicKeyNotFoundError(userId);
  }

  let challenge: Uint8Array | null;
  try {
    challenge = await options.store.consumeIfLive(userId);
  } catch (e) {
    throw new InternalError(
      `Challenge store consumeIfLive threw during rekey: ${
        e instanceof Error ? e.message : String(e)
      }`,
    );
  }

  if (challenge === null) {
    throw new ChallengeExpiredError();
  }

  let valid: boolean;
  try {
    valid = verifyProof(currentPublicKey, challenge, proof);
  } catch (e) {
    if (e instanceof InvalidInputError) {
      throw new InternalError(`verifyProof threw ${e.code}: ${e.message}`);
    }
    throw new InternalError(
      `verifyProof threw unexpectedly during rekey: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  if (!valid) {
    throw new ProofInvalidError();
  }

  try {
    await options.savePublicKey(userId, newPublicKey);
  } catch (e) {
    throw new InternalError(
      `savePublicKey threw during rekey: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  return { status: 'rekeyed', userId };
}

// ---------------------------------------------------------------------------
// Express middleware
// ---------------------------------------------------------------------------

export function zkpRekey(options: ZkpRekeyOptions): RequestHandler {
  return async (req, res, next): Promise<void> => {
    const startedAt = Date.now();
    const ip = getRequestIp(req);
    const userId = extractUserIdForAudit(req.body as unknown);

    if (options.authRateLimiter !== false) {
      try {
        await enforceAuthRateLimit(req, options.authRateLimiter);
      } catch {
        await auditKeyOverwriteAttempt(options, userId, ip, false, 'rate_limited');
        await waitForMinimumRekeyDuration(startedAt, options);
        const err = new RateLimitedError();
        res.status(err.httpStatus).json(toErrorBody(err));
        return;
      }
    }

    if (options.rateLimitHook !== undefined) {
      try {
        await options.rateLimitHook(req);
      } catch {
        await auditKeyOverwriteAttempt(options, userId, ip, false, 'rate_limit_hook');
        await waitForMinimumRekeyDuration(startedAt, options);
        const err = new RateLimitedError();
        res.status(err.httpStatus).json(toErrorBody(err));
        return;
      }
    }

    try {
      const result = await handleRekey(req.body as unknown, options);
      await auditKeyOverwriteAttempt(options, result.userId, ip, true, 'rekey_success');
      res.status(200).json(result);
    } catch (e) {
      if (e instanceof ServerError) {
        await auditKeyOverwriteAttempt(options, userId, ip, false, e.code.toLowerCase());
        res.status(e.httpStatus).json(toErrorBody(e));
        return;
      }
      await auditKeyOverwriteAttempt(options, userId, ip, false, 'internal_error');
      next(e);
    }
  };
}

function extractUserIdForAudit(body: unknown): string {
  if (body !== null && typeof body === 'object') {
    const raw = body as Record<string, unknown>;
    if (typeof raw['userId'] === 'string') {
      return raw['userId'];
    }
  }
  return '';
}

async function auditKeyOverwriteAttempt(
  options: ZkpRekeyOptions,
  userId: string,
  ip: string,
  success: boolean,
  reason: string,
): Promise<void> {
  await logKeyOverwriteAttempt(
    {
      userId,
      ip,
      success,
      reason,
    },
    options.auditLogger,
  );
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

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
  if (typeof raw['newPublicKeyHex'] !== 'string' || raw['newPublicKeyHex'].length === 0) {
    throw new MissingFieldError('newPublicKeyHex');
  }

  return {
    userId: raw['userId'],
    proofHex: raw['proofHex'],
    newPublicKeyHex: raw['newPublicKeyHex'],
  };
}

function decodeProofHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]{128}$/.test(hex)) {
    throw new InvalidEncodingError('proofHex', 'must be exactly 128 hex characters (64 bytes)');
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

function decodePublicKeyHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new InvalidEncodingError(
      'newPublicKeyHex',
      'must be exactly 64 hex characters (32 bytes)',
    );
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

function validatePublicKey(publicKey: Uint8Array, field: string): void {
  const dummyChallenge = new Uint8Array(32);
  const dummyProof = new Uint8Array(64);
  dummyProof[32] = 1;

  try {
    verifyProof(publicKey, dummyChallenge, dummyProof);
  } catch (e) {
    if (e instanceof InvalidInputError && e.code === 'INVALID_PUBLIC_KEY') {
      throw new InvalidEncodingError(
        field,
        `Public key is not a valid Ed25519 point: ${e.message}`,
      );
    }
    throw new InternalError(
      `Unexpected error during public key validation: ${
        e instanceof Error ? e.message : String(e)
      }`,
    );
  }
}

async function waitForMinimumRekeyDuration(
  startedAt: number,
  options: ZkpRekeyOptions,
): Promise<void> {
  const minimumMs =
    typeof options.minRekeyResponseMs === 'number' &&
    Number.isFinite(options.minRekeyResponseMs) &&
    options.minRekeyResponseMs >= 0
      ? options.minRekeyResponseMs
      : DEFAULT_MIN_REKEY_RESPONSE_MS;
  const remainingMs = minimumMs - (Date.now() - startedAt);
  if (remainingMs <= 0) {
    return;
  }
  await new Promise<void>((resolve) => {
    setTimeout(resolve, remainingMs);
  });
}
