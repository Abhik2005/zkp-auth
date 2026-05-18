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
import type { ZkpRegisterOptions } from '../types.js';

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
 * @param options `ZkpRegisterOptions` including `savePublicKey` hook and
 *                optional `rateLimitHook`.
 * @returns       Express `RequestHandler`.
 *
 * @example
 * ```ts
 * app.post('/auth/register', express.json(), zkpRegister({
 *   savePublicKey: db.savePublicKey,
 * }));
 * ```
 */
export function zkpRegister(options: ZkpRegisterOptions): RequestHandler {
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
      const result = await handleRegister(req.body as unknown, options);
      res.status(201).json(result);
    } catch (e) {
      if (e instanceof ServerError) {
        res.status(e.httpStatus).json(toErrorBody(e));
        return;
      }
      // Unexpected error — pass to Express error handler.
      next(e);
    }
  };
}
