/**
 * @zkp-auth/server — Express adapter for zkpChallenge
 *
 * Thin adapter that calls `handleChallenge` and maps the result or any
 * `ServerError` to the appropriate HTTP response.
 */

import type { RequestHandler } from 'express';
import { handleChallenge } from '../core/challenge.js';
import { ServerError, toErrorBody, RateLimitedError } from '../errors.js';
import { enforceAuthRateLimit } from '../rate-limit.js';
import type { ZkpChallengeOptions } from '../types.js';

/**
 * Express middleware factory for challenge issuance.
 *
 * Expects a JSON body: `{ userId: string }`.
 *
 * On success responds with HTTP 200:
 * ```json
 * { "status": "challenge_issued", "challengeHex": "...", "expiresInMs": 60000 }
 * ```
 *
 * On failure responds with HTTP 4xx/5xx:
 * ```json
 * { "error": { "code": "...", "message": "..." } }
 * ```
 *
 * @param options `ZkpChallengeOptions` including `store`, optional `ttlMs`,
 *                and optional `rateLimitHook`.
 * @returns       Express `RequestHandler`.
 *
 * @example
 * ```ts
 * const store = new InMemoryChallengeStore();
 * app.post('/auth/challenge', express.json(), zkpChallenge({ store, ttlMs: 60_000 }));
 * ```
 */
export function zkpChallenge(options: ZkpChallengeOptions): RequestHandler {
  return async (req, res, next): Promise<void> => {
    if (options.authRateLimiter !== false) {
      try {
        await enforceAuthRateLimit(req, options.authRateLimiter);
      } catch {
        const err = new RateLimitedError();
        res.status(err.httpStatus).json(toErrorBody(err));
        return;
      }
    }

    // Rate-limit hook (if provided)
    if (options.rateLimitHook !== undefined) {
      try {
        await options.rateLimitHook(req);
      } catch {
        const err = new RateLimitedError();
        res.status(err.httpStatus).json(toErrorBody(err));
        return;
      }
    }

    try {
      const result = await handleChallenge(req.body as unknown, options);
      res.status(200).json(result);
    } catch (e) {
      if (e instanceof ServerError) {
        res.status(e.httpStatus).json(toErrorBody(e));
        return;
      }
      next(e);
    }
  };
}
