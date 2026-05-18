/**
 * @zkp-auth/server — Express Request type augmentation
 *
 * Extends `Express.Request` via the global `Express` namespace — the same
 * pattern used by Passport.js and every other Express middleware that adds
 * properties to `req`. `@types/express-serve-static-core` merges
 * `Express.Request` into its own `Request<P,ResBody,ReqBody,Query,Locals>`
 * interface, so this approach works regardless of module resolution mode
 * or package manager (pnpm, npm, yarn).
 *
 * This file MUST be imported as a regular (non-type) side-effect import so
 * TypeScript processes the `declare global` block:
 *   import './express-augmentation.js'   ← in src/index.ts
 */

import type { ZkpUser } from './types.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /**
       * Set by `zkpVerify` middleware after successful proof verification.
       * Undefined on every other route.
       */
      zkpUser?: ZkpUser;
    }
  }
}

export {};
