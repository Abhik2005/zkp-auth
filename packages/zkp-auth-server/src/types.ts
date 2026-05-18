/**
 * @zkp-auth/server — shared option types and request/response shapes
 *
 * This module defines the public TypeScript API surface for all three
 * middleware factories. All types are framework-agnostic; the Express
 * adapters in `middleware/` are the only consumers of Express-specific
 * imports.
 */

import type { Request } from 'express';

// ---------------------------------------------------------------------------
// Rate-limit hook
// ---------------------------------------------------------------------------

/**
 * Optional async hook that the caller provides to enforce rate limiting.
 *
 * The hook receives the Express `Request` and must:
 * - resolve `void` when the request is allowed, OR
 * - throw / reject when the request should be blocked.
 *
 * The middleware wraps the throw in a `RateLimitedError` (HTTP 429).
 * The hook itself may choose a different rejection strategy (e.g. call
 * `res.end()` directly via a closure) — the middleware always checks for
 * rejection first.
 *
 * Example (express-rate-limit integration):
 * ```ts
 * const limiter = rateLimit({ windowMs: 60_000, max: 10 });
 * zkpChallenge({ rateLimitHook: (req) => new Promise((resolve, reject) => {
 *   limiter(req, {} as Response, (err) => (err != null ? reject(err) : resolve()));
 * }) });
 * ```
 */
export type RateLimitHook = (req: Request) => Promise<void>;

// ---------------------------------------------------------------------------
// Public key lookup
// ---------------------------------------------------------------------------

/**
 * Async hook the caller provides to look up a registered Ed25519 public key.
 *
 * @param userId The user identifier extracted from the request body.
 * @returns      A 32-byte `Uint8Array` if the user is registered, or `null`
 *               if no key exists for that user.
 */
export type GetPublicKeyFn = (userId: string) => Promise<Uint8Array | null>;

/**
 * Async hook called after successful proof verification to persist a new
 * public key registration.
 *
 * Callers are responsible for deduplication / upsert semantics.
 *
 * @param userId    The user identifier from the request body.
 * @param publicKey The 32-byte Ed25519 public key.
 */
export type SavePublicKeyFn = (userId: string, publicKey: Uint8Array) => Promise<void>;

// ---------------------------------------------------------------------------
// Challenge store interface (injectable)
// ---------------------------------------------------------------------------

/**
 * The server-wide challenge store.
 *
 * The default implementation (`InMemoryChallengeStore`) lives in
 * `challenge-store.ts`. Callers may supply any object satisfying this
 * interface (e.g. a Redis-backed store).
 */
export interface IChallengeStore {
  /**
   * Store a challenge for `sessionId`.
   *
   * Replaces any existing challenge for that `sessionId`. The store is
   * responsible for expiring the challenge after `ttlMs` milliseconds.
   *
   * @param sessionId A unique session identifier (e.g. userId).
   * @param challenge 32-byte challenge bytes.
   * @param ttlMs     Time-to-live in milliseconds.
   */
  set(sessionId: string, challenge: Uint8Array, ttlMs: number): Promise<void>;

  /**
   * Atomically retrieve and delete a challenge for `sessionId`.
   *
   * Returns `null` when no live, non-expired challenge exists.  Returning
   * `null` for a replayed challenge (consumed twice) is how the store
   * enforces replay prevention — the second call always returns `null`.
   *
   * @param sessionId A unique session identifier.
   * @returns         The 32-byte challenge if live, or `null`.
   */
  consumeIfLive(sessionId: string): Promise<Uint8Array | null>;
}

// ---------------------------------------------------------------------------
// zkpRegister options
// ---------------------------------------------------------------------------

/**
 * Options for `zkpRegister(options)`.
 *
 * @example
 * ```ts
 * app.post('/auth/register', zkpRegister({
 *   savePublicKey: db.users.savePublicKey,
 * }));
 * ```
 */
export interface ZkpRegisterOptions {
  /**
   * Persist the user's public key.
   * Called only after input validation succeeds.
   */
  savePublicKey: SavePublicKeyFn;
  /** Optional rate-limiter hook. Called before any processing. */
  rateLimitHook?: RateLimitHook;
}

// ---------------------------------------------------------------------------
// zkpChallenge options
// ---------------------------------------------------------------------------

/**
 * Options for `zkpChallenge(options)`.
 *
 * @example
 * ```ts
 * app.post('/auth/challenge', zkpChallenge({ store }));
 * ```
 */
export interface ZkpChallengeOptions {
  /** Challenge store. Defaults to the module-level shared `InMemoryChallengeStore`. */
  store: IChallengeStore;
  /** Challenge TTL in milliseconds. Default: 60_000 (60 seconds). */
  ttlMs?: number;
  /** Optional rate-limiter hook. Called before any processing. */
  rateLimitHook?: RateLimitHook;
}

// ---------------------------------------------------------------------------
// zkpVerify options
// ---------------------------------------------------------------------------

/**
 * Options for `zkpVerify(options)`.
 *
 * On success the middleware:
 *  1. Attaches `{ userId }` to `req.zkpUser`.
 *  2. Signs and attaches a JWT to `res.locals.zkpToken` (string).
 *  3. Calls `next()` — the route handler may read both.
 *
 * @example
 * ```ts
 * app.post('/auth/verify', zkpVerify({
 *   getPublicKey: db.users.getPublicKey,
 *   store,
 *   jwtSecret: process.env.JWT_SECRET!,
 * }), (req, res) => res.json({ token: res.locals.zkpToken }));
 * ```
 */
export interface ZkpVerifyOptions {
  /** Retrieve the registered public key for `userId`. */
  getPublicKey: GetPublicKeyFn;
  /** Challenge store — must be the same instance used for `zkpChallenge`. */
  store: IChallengeStore;
  /** HMAC-SHA256 secret for JWT signing. Must be ≥ 32 bytes when UTF-8 encoded. */
  jwtSecret: string;
  /** JWT expiry in seconds. Default: 3600 (1 hour). */
  jwtExpiresInSeconds?: number;
  /** Optional rate-limiter hook. Called before any processing. */
  rateLimitHook?: RateLimitHook;
}

// ---------------------------------------------------------------------------
// req.zkpUser augmentation (ambient)
// ---------------------------------------------------------------------------

/**
 * Attached to `req.zkpUser` by `zkpVerify` upon successful verification.
 */
export interface ZkpUser {
  /** The authenticated user identifier from the request body. */
  userId: string;
}


// ---------------------------------------------------------------------------
// Wire-format shapes for request bodies
// ---------------------------------------------------------------------------

/**
 * Expected JSON body for `POST /auth/register`.
 * Field names are lower_snake_case to match idiomatic REST conventions.
 */
export interface RegisterRequestBody {
  /** User identifier string. */
  userId: string;
  /** Hex-encoded 32-byte Ed25519 public key. */
  publicKeyHex: string;
}

/**
 * Expected JSON body for `POST /auth/challenge`.
 */
export interface ChallengeRequestBody {
  /** User identifier string. */
  userId: string;
}

/**
 * Expected JSON body for `POST /auth/verify`.
 */
export interface VerifyRequestBody {
  /** User identifier string — used to look up the public key. */
  userId: string;
  /** Hex-encoded 64-byte proof `R_bytes || s_bytes`. */
  proofHex: string;
}
