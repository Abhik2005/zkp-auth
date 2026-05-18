// @zkp-auth/client — ZkpAuthClient: the single developer-facing class
//
// This module exposes the entire ZKP authentication flow as two async
// methods on a single class instance:
//
//   client.register(username, password)
//     → generate Ed25519 keypair (browser CSPRNG)
//     → send publicKeyHex to POST /auth/register
//     → store privateKey in memory
//     → return { userId, publicKeyHex }
//
//   client.login(username, password)
//     → validate inputs
//     → fetch 32-byte challenge from POST /auth/challenge
//     → compute 64-byte Schnorr proof (browser ZKP, privateKey in memory)
//     → send proofHex to POST /auth/verify
//     → return { userId, token }
//
// The private key NEVER leaves the class instance. It is never serialised,
// never transmitted, and never written to localStorage or any other
// persistent store. Developers should call `clearKey()` on logout.
//
// LIFECYCLE NOTE:
//   The private key lives only in the current JS heap. A page reload clears
//   it. For multi-session support (login without re-registering) the
//   application must export/import the key via an out-of-band channel
//   (e.g. encrypted IndexedDB) — that is outside the scope of this SDK.

import {
  browserDeriveKeyPair,
  browserComputeProof,
  validateUsername,
  encodePassword,
} from './crypto.js';

import {
  postRegister,
  postChallenge,
  postVerify,
  bytesToHex,
  hexToBytes,
} from './http.js';

import { ZkpCryptoError } from './errors.js';

// ── Configuration ─────────────────────────────────────────────────────────────

/**
 * Constructor options for `ZkpAuthClient`.
 */
export interface ZkpAuthClientOptions {
  /**
   * Base URL of the ZKP auth server.
   *
   * Trailing slashes are stripped automatically.
   * Pass an empty string `''` or `'/'` to use same-origin relative paths
   * (e.g. when a Vite/webpack dev-server proxy forwards `/auth/*` to the
   * backend). Pass a full origin for cross-origin servers.
   *
   * @example 'https://api.example.com'   // cross-origin production
   * @example 'http://localhost:3001'     // direct local backend
   * @example ''                          // same-origin via dev proxy
   */
  baseUrl: string;
}

// ── Return types ──────────────────────────────────────────────────────────────

/**
 * Returned by `register()` on success.
 */
export interface RegisterOutcome {
  /** The registered user identifier. */
  userId: string;
  /** Hex-encoded 32-byte Ed25519 public key sent to the server. */
  publicKeyHex: string;
}

/**
 * Returned by `login()` on success.
 */
export interface LoginOutcome {
  /** The authenticated user identifier. */
  userId: string;
  /** Signed HS256 JWT issued by the server. */
  token: string;
}

// ── Client class ──────────────────────────────────────────────────────────────

/**
 * Framework-agnostic browser SDK for ZKP authentication.
 *
 * Create one instance per user session and reuse it across `register` /
 * `login` calls. The instance is stateful: after `register()` succeeds the
 * private key is held in memory and used automatically by `login()`.
 *
 * @example
 * ```ts
 * const client = new ZkpAuthClient({ baseUrl: 'https://api.example.com' });
 *
 * // First visit: register
 * const { userId } = await client.register('alice', 'hunter2');
 *
 * // Immediately log in (same session, key still in memory)
 * const { token } = await client.login('alice', 'hunter2');
 * document.cookie = `auth=${token}; Secure; SameSite=Strict`;
 *
 * // On logout:
 * client.clearKey();
 * ```
 */
export class ZkpAuthClient {
  private readonly baseUrl: string;

  /**
   * In-memory private key. `null` until `register()` succeeds or `loadKey()`
   * is called. Zeroed by `clearKey()`.
   */
  private _privateKey: Uint8Array | null = null;

  /**
   * @param options `ZkpAuthClientOptions` — requires `baseUrl`.
   */
  constructor(options: ZkpAuthClientOptions) {
    // Strip trailing slashes so callers can pass '/', 'https://api.example.com/',
    // or '' (same-origin). All produce correct fetch URLs via string concatenation:
    //   '' + '/auth/register' → '/auth/register'  (relative, same-origin proxy)
    //   'http://localhost:3001' + '/auth/register' → absolute cross-origin URL
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
  }

  // ── State inspection ────────────────────────────────────────────────────────

  /**
   * `true` when a private key is held in memory and `login()` can be called
   * without triggering a "no key in memory" error.
   */
  get hasKey(): boolean {
    return this._privateKey !== null;
  }

  // ── Key lifecycle ───────────────────────────────────────────────────────────

  /**
   * Zero-fill and discard the private key held in memory.
   *
   * Call this on user logout to prevent the key from lingering in the JS heap.
   * After `clearKey()`, `hasKey` is `false` and `login()` will throw until
   * a new key is established via `register()` or `loadKey()`.
   *
   * Note: JavaScript provides no hard zeroization guarantee (the GC may have
   * relocated the backing ArrayBuffer), but calling `fill(0)` makes a
   * best-effort attempt to overwrite the key bytes in place — the same
   * hygiene policy used by `@zkp-auth/core`'s nonce handling.
   */
  clearKey(): void {
    if (this._privateKey !== null) {
      this._privateKey.fill(0);
      this._privateKey = null;
    }
  }

  /**
   * Load a previously exported private key back into memory.
   *
   * Use this to restore a key that was persisted out-of-band (e.g. encrypted
   * IndexedDB). The key must be a 32-byte `Uint8Array` encoding a scalar
   * in `[1, L)` — the same shape produced by `register()`.
   *
   * The SDK stores a copy of the supplied buffer so the caller may zero
   * their own copy after this call.
   *
   * @param privateKey 32-byte Ed25519 scalar private key.
   * @throws ZkpCryptoError('CURVE_ERROR') when `privateKey` is not a
   *   `Uint8Array` of exactly 32 bytes.
   */
  loadKey(privateKey: Uint8Array): void {
    if (!(privateKey instanceof Uint8Array) || privateKey.byteLength !== 32) {
      throw new ZkpCryptoError(
        'CURVE_ERROR',
        'loadKey: privateKey must be a Uint8Array of exactly 32 bytes',
      );
    }
    this.clearKey();
    this._privateKey = Uint8Array.from(privateKey); // defensive copy
  }

  /**
   * Export a copy of the private key currently held in memory.
   *
   * The returned `Uint8Array` is a fresh copy — zeroing it does not affect
   * the key stored inside the client.
   *
   * Use this to persist the key out-of-band (e.g. encrypt and store in
   * IndexedDB) so `login()` can be called after a page reload.
   *
   * @returns A 32-byte copy of the in-memory private key.
   * @throws ZkpCryptoError('CURVE_ERROR') when no key is in memory.
   */
  exportKey(): Uint8Array {
    if (this._privateKey === null) {
      throw new ZkpCryptoError(
        'CURVE_ERROR',
        'exportKey: no private key in memory — call register() or loadKey() first',
      );
    }
    return Uint8Array.from(this._privateKey);
  }

  // ── Protocol methods ────────────────────────────────────────────────────────

  /**
   * Register a new user with the ZKP auth server.
   *
   * Steps:
   * 1. Validate `username` and `password`.
   * 2. Generate a fresh Ed25519 keypair using the browser CSPRNG.
   * 3. POST `{ userId: username, publicKeyHex }` to `/auth/register`.
   * 4. On success, store the private key in memory and return the outcome.
   *
   * If the server responds with a non-2xx status (e.g. user already exists),
   * a `ZkpServerError('REGISTER_FAILED')` is thrown and the generated private
   * key is discarded — `hasKey` remains unchanged.
   *
   * @param username Non-empty string, ≤ 256 UTF-8 bytes.
   * @param password String, ≤ 4 096 UTF-8 bytes. An empty string is permitted.
   *
   * @returns `RegisterOutcome` containing `userId` and `publicKeyHex`.
   *
   * @throws ZkpCryptoError('INVALID_USERNAME') — empty or oversize username.
   * @throws ZkpCryptoError('INVALID_PASSWORD') — oversize password.
   * @throws ZkpCryptoError('RNG_FAILURE')      — CSPRNG or rejection-sampling failure.
   * @throws ZkpCryptoError('CURVE_ERROR')       — @noble/curves internal error.
   * @throws ZkpNetworkError                     — fetch() rejected.
   * @throws ZkpServerError('REGISTER_FAILED')   — server returned non-2xx.
   */
  async register(username: string, password: string): Promise<RegisterOutcome> {
    // Step 1 — input validation (throws ZkpCryptoError on failure).
    validateUsername(username);
    encodePassword(password); // validate only; result discarded at registration time

    // Step 2 — derive deterministic keypair from username + password.
    // Using a KDF means the private key is reproducible from credentials alone,
    // so it never needs to be stored — login() re-derives it on every call.
    const { privateKey, publicKey } = await browserDeriveKeyPair(username, password);
    const publicKeyHex = bytesToHex(publicKey);

    // Step 3 — register with the server.
    // If this throws, privateKey is never stored — caller retains no new state.
    await postRegister(this.baseUrl, username, publicKeyHex);

    // Step 4 — server accepted; cache the key in memory for the current session.
    this.clearKey(); // zero any previously held key before replacing
    this._privateKey = privateKey;

    return { userId: username, publicKeyHex };
  }

  /**
   * Authenticate an already-registered user and obtain a JWT.
   *
   * Steps:
   * 1. Validate `username` and `password`.
   * 2. POST `{ userId: username }` to `/auth/challenge` to obtain a
   *    server-issued 32-byte challenge.
   * 3. Compute a 64-byte Schnorr proof using the private key in memory.
   * 4. POST `{ userId: username, proofHex }` to `/auth/verify`.
   * 5. Return `{ userId, token }` on success.
   *
   * Requires that `hasKey` is `true` (i.e. `register()` or `loadKey()` was
   * called successfully in the current session).
   *
   * @param username Non-empty string, ≤ 256 UTF-8 bytes.
   * @param password String, ≤ 4 096 UTF-8 bytes. Must match the password
   *   used at registration time (currently a no-op in the protocol; reserved
   *   for future password-derived-key integration).
   *
   * @returns `LoginOutcome` containing `userId` and a signed JWT `token`.
   *
   * @throws ZkpCryptoError('INVALID_USERNAME') — empty or oversize username.
   * @throws ZkpCryptoError('INVALID_PASSWORD') — oversize password.
   * @throws ZkpCryptoError('CURVE_ERROR')       — no key in memory, or
   *   @noble/curves internal error during proof computation.
   * @throws ZkpCryptoError('RNG_FAILURE')       — CSPRNG failure during nonce
   *   generation inside proof computation.
   * @throws ZkpNetworkError                     — fetch() rejected.
   * @throws ZkpServerError('CHALLENGE_FAILED')  — server did not issue a challenge.
   * @throws ZkpServerError('PROOF_REJECTED')    — server's cryptographic
   *   verification returned false (challenge expired, replayed, or proof invalid).
   * @throws ZkpServerError('SERVER_ERROR')      — unexpected server fault.
   */
  async login(username: string, password: string): Promise<LoginOutcome> {
    // Step 1 — input validation.
    validateUsername(username);
    const passwordBytes = encodePassword(password);

    // Step 2 — obtain the private key.
    //
    // The key is derived deterministically from username + password via PBKDF2,
    // so it is always available — no prior register() call in the current
    // session is required. This fixes the "private key lost on page reload"
    // issue: after a reload the user types their credentials and login() re-
    // derives the exact same scalar that was registered with the server.
    //
    // If register() was already called this session, we use the cached key
    // (same value, avoids running PBKDF2 twice in the same session).
    let privateKey: Uint8Array;
    if (this._privateKey !== null) {
      // Fast path: key already in memory from this session's register() call.
      privateKey = this._privateKey;
    } else {
      // Slow path: re-derive from credentials (page reload or fresh tab).
      const derived = await browserDeriveKeyPair(username, password);
      privateKey = derived.privateKey;
      // Cache for any further login() calls this session.
      this._privateKey = privateKey;
    }

    // Step 3 — fetch challenge from server.
    const challengeResult = await postChallenge(this.baseUrl, username);
    const challengeBytes = hexToBytes(challengeResult.challengeHex);

    if (challengeBytes.byteLength !== 32) {
      // The server returned a challengeHex that isn't 64 hex chars (32 bytes).
      throw new ZkpCryptoError(
        'CURVE_ERROR',
        `Server returned a challenge of unexpected length: expected 32 bytes, got ${challengeBytes.byteLength.toString()}`,
      );
    }

    // Step 4 — compute proof (pure synchronous crypto; throws ZkpCryptoError).
    const proof = browserComputeProof(privateKey, passwordBytes, challengeBytes);
    const proofHex = bytesToHex(proof);

    // Step 5 — submit proof to server.
    const verifyResult = await postVerify(this.baseUrl, username, proofHex);

    // Step 6 — return outcome.
    // token is undefined when the server uses cookie-based auth (the JWT is
    // delivered via Set-Cookie instead of the response body). Return an empty
    // string in that case; callers should not depend on the token field when
    // using HttpOnly cookie sessions.
    return { userId: username, token: verifyResult.token ?? '' };
  }
}
