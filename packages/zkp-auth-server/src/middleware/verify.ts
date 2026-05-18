/**
 * @zkp-auth/server — Express adapter for zkpVerify
 *
 * Thin adapter that calls `handleVerify` and maps the result or any
 * `ServerError` to the appropriate HTTP response.
 *
 * On success:
 * - Attaches `{ userId }` to `req.zkpUser` for downstream handlers.
 * - Attaches the JWT string to `res.locals.zkpToken`.
 * - Calls `next()` so the route handler can decide how to return the token.
 *
 * The route handler is responsible for sending the final response, e.g.:
 * ```ts
 * app.post('/auth/verify', zkpVerify(opts), (req, res) => {
 *   res.json({ token: res.locals.zkpToken, userId: req.zkpUser!.userId });
 * });
 * ```
 */

import type { RequestHandler } from 'express';
import { handleVerify } from '../core/verify.js';
import { ServerError, toErrorBody, RateLimitedError } from '../errors.js';
import type { ZkpVerifyOptions } from '../types.js';

/**
 * Express middleware factory for proof verification and JWT issuance.
 *
 * Expects a JSON body: `{ userId: string, proofHex: string }`.
 *
 * On success (HTTP is left to the downstream handler — call `next()`):
 * - `req.zkpUser` = `{ userId: string }`
 * - `res.locals.zkpToken` = signed JWT string
 *
 * On failure responds with HTTP 4xx/5xx:
 * ```json
 * { "error": { "code": "...", "message": "..." } }
 * ```
 *
 * @param options `ZkpVerifyOptions` including `getPublicKey`, `store`,
 *                `jwtSecret`, optional `jwtExpiresInSeconds`, and optional
 *                `rateLimitHook`.
 * @returns       Express `RequestHandler`.
 *
 * @example
 * ```ts
 * app.post('/auth/verify', express.json(),
 *   zkpVerify({ getPublicKey, store, jwtSecret: process.env.JWT_SECRET! }),
 *   (req, res) => res.json({ token: res.locals.zkpToken }),
 * );
 * ```
 */
export function zkpVerify(options: ZkpVerifyOptions): RequestHandler {
  return async (req, res, next): Promise<void> => {
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
      const result = await handleVerify(req.body as unknown, options);

      // Attach to req / res.locals for downstream handlers.
      req.zkpUser = { userId: result.userId };
      res.locals['zkpToken'] = result.token;

      // Do NOT send a response — let the route handler decide the final shape.
      next();
    } catch (e) {
      if (e instanceof ServerError) {
        res.status(e.httpStatus).json(toErrorBody(e));
        return;
      }
      next(e);
    }
  };
}
