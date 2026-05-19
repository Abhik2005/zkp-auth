/**
 * @zkp-auth/server — Express adapter for zkpRegister
 *
 * Thin adapter that calls `handleRegister` and maps the result or any
 * `ServerError` to the appropriate HTTP response.
 */

import type { RequestHandler } from 'express';
import { handleRegister } from '../core/register.js';
import { ServerError, toErrorBody } from '../errors.js';
import { RateLimitedError } from '../errors.js';
import { logKeyOverwriteAttempt, logRegistrationAttempt } from '../audit-log.js';
import {
  checkRegistrationRateLimit,
  getRequestIp,
} from '../rate-limit.js';
import type { ZkpRegisterOptions } from '../types.js';

const DEFAULT_MIN_REGISTER_RESPONSE_MS = 150;

/**
 * Express middleware factory for user registration.
 *
 * Expects a JSON body: `{ userId: string, publicKeyHex: string }`.
 *
 * On success responds with HTTP 201:
 * ```json
 * { "status": "registered", "userId": "..." }
 * ```
 *
 * On failure responds with HTTP 4xx/5xx:
 * ```json
 * { "error": { "code": "...", "message": "..." } }
 * ```
 *
 * @param options `ZkpRegisterOptions` including `getPublicKey` /
 *                `savePublicKey` hooks and optional `rateLimitHook`.
 * @returns       Express `RequestHandler`.
 *
 * @example
 * ```ts
 * app.post('/auth/register', express.json(), zkpRegister({
 *   getPublicKey: db.getPublicKey,
 *   savePublicKey: db.createPublicKey,
 * }));
 * ```
 */
export function zkpRegister(options: ZkpRegisterOptions): RequestHandler {
  return async (req, res, next): Promise<void> => {
    const startedAt = Date.now();
    const ip = getRequestIp(req);
    const userId = extractUserIdForAudit(req.body as unknown);

    const rateLimitDecision = checkRegistrationRateLimit(
      ip,
      options.registrationRateLimiter,
    );
    if (!rateLimitDecision.allowed) {
      await auditRegistrationAttempt(options, {
        userId,
        ip,
        success: false,
        reason: rateLimitDecision.reason,
        timestamp: rateLimitDecision.timestampMs,
      });
      await waitForMinimumRegisterDuration(startedAt, options);
      const err = new RateLimitedError();
      res.status(err.httpStatus).json(toErrorBody(err));
      return;
    }

    // Optional caller-provided rate-limit hook. The built-in registration
    // limiter always runs first; this hook lets applications add stricter
    // global/user-agent/account-level policy without disabling the default.
    if (options.rateLimitHook !== undefined) {
      try {
        await options.rateLimitHook(req);
      } catch {
        await auditRegistrationAttempt(options, {
          userId,
          ip,
          success: false,
          reason: 'rate_limit_hook',
        });
        await waitForMinimumRegisterDuration(startedAt, options);
        const err = new RateLimitedError();
        res.status(err.httpStatus).json(toErrorBody(err));
        return;
      }
    }

    try {
      const result = await handleRegister(req.body as unknown, {
        ...options,
        minRegisterResponseMs: 0,
      });
      await auditRegistrationAttempt(options, {
        userId: result.userId,
        ip,
        success: true,
      });
      await waitForMinimumRegisterDuration(startedAt, options);
      res.status(201).json(result);
    } catch (e) {
      if (e instanceof ServerError) {
        const reason = e.code.toLowerCase();
        await auditRegistrationAttempt(options, {
          userId,
          ip,
          success: false,
          reason,
        });
        if (e.code === 'REGISTRATION_FAILED') {
          await auditKeyOverwriteAttempt(options, {
            userId,
            ip,
            success: false,
            reason,
          });
        }
        await waitForMinimumRegisterDuration(startedAt, options);
        res.status(e.httpStatus).json(toErrorBody(e));
        return;
      }
      // Unexpected error — pass to Express error handler.
      await auditRegistrationAttempt(options, {
        userId,
        ip,
        success: false,
        reason: 'internal_error',
      });
      await waitForMinimumRegisterDuration(startedAt, options);
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

async function auditRegistrationAttempt(
  options: ZkpRegisterOptions,
  input: Parameters<typeof logRegistrationAttempt>[0],
): Promise<void> {
  await logRegistrationAttempt(input, options.auditLogger);
}

async function auditKeyOverwriteAttempt(
  options: ZkpRegisterOptions,
  input: Parameters<typeof logKeyOverwriteAttempt>[0],
): Promise<void> {
  await logKeyOverwriteAttempt(input, options.auditLogger);
}

async function waitForMinimumRegisterDuration(
  startedAt: number,
  options: ZkpRegisterOptions,
): Promise<void> {
  const minimumMs =
    typeof options.minRegisterResponseMs === 'number' &&
    Number.isFinite(options.minRegisterResponseMs) &&
    options.minRegisterResponseMs >= 0
      ? options.minRegisterResponseMs
      : DEFAULT_MIN_REGISTER_RESPONSE_MS;
  const remainingMs = minimumMs - (Date.now() - startedAt);
  if (remainingMs <= 0) {
    return;
  }
  await new Promise<void>((resolve) => {
    setTimeout(resolve, remainingMs);
  });
}
