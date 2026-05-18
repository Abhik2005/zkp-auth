// @zkp-auth/react — shared type definitions
//
// All public-facing interfaces for the React layer live here.
// No runtime code; import-only. This keeps the context, provider, and
// hooks all working off one source of truth for the data shapes.

import type { ZkpClientError } from '@zkp-auth/client';

// ── User shape ───────────────────────────────────────────────────────────────

/**
 * Represents the currently authenticated user held in React context.
 *
 * - `userId`       — the username supplied at registration / login.
 * - `token`        — the signed JWT returned by the server on login.
 *                    `null` immediately after `register()` (key generated,
 *                    but no login call made yet).
 * - `publicKeyHex` — hex-encoded Ed25519 public key registered with the
 *                    server. Available after `register()`; `null` when the
 *                    user was restored from a token without re-registering.
 */
export interface ZKPUser {
  /** Username / user identifier. */
  readonly userId: string;
  /** Signed HS256 JWT. `null` until the first successful `login()`. */
  readonly token: string | null;
  /** Hex-encoded Ed25519 public key. `null` when registered in a prior session. */
  readonly publicKeyHex: string | null;
}

// ── Auth state ───────────────────────────────────────────────────────────────

/**
 * The complete auth state held by `ZKPProvider`.
 *
 * Consumers should read this via `useZKPAuth()` or `useZKPUser()`.
 */
export interface ZKPAuthState {
  /**
   * The currently authenticated user, or `null` when unauthenticated.
   * Guaranteed non-null when `isAuthenticated` is `true`.
   */
  readonly user: ZKPUser | null;

  /**
   * `true` when a JWT-bearing user is present in context.
   * Note: this is a client-side flag only — the JWT is not re-validated
   * against the server on mount. Validate server-side on protected requests.
   */
  readonly isAuthenticated: boolean;

  /**
   * `true` while `register()` or `login()` is in flight.
   * Always `false` at rest.
   */
  readonly loading: boolean;

  /**
   * The last error thrown by `register()` or `login()`, or `null` when none.
   * Typed as the base `ZkpClientError` so callers can narrow on `.code`.
   */
  readonly error: ZkpClientError | null;
}

// ── Context value ─────────────────────────────────────────────────────────────

/**
 * Full value shape of the internal `ZKPContext`.
 *
 * Extends `ZKPAuthState` with the mutable operations exposed by `useZKPAuth()`.
 */
export interface ZKPContextValue extends ZKPAuthState {
  /**
   * Register a new user.
   *
   * Sets `loading = true`, calls `ZkpAuthClient.register()`, updates `user`
   * with the resulting `userId` and `publicKeyHex`, then sets `loading = false`.
   * On failure, `error` is set and `user` remains unchanged.
   *
   * @param username Non-empty string, ≤ 256 UTF-8 bytes.
   * @param password String, ≤ 4 096 UTF-8 bytes.
   */
  register(username: string, password: string): Promise<void>;

  /**
   * Authenticate an already-registered user.
   *
   * Sets `loading = true`, calls `ZkpAuthClient.login()`, updates `user`
   * with `userId` and `token`, sets `isAuthenticated = true`, then sets
   * `loading = false`. On failure, `error` is set.
   *
   * @param username Non-empty string, ≤ 256 UTF-8 bytes.
   * @param password String, ≤ 4 096 UTF-8 bytes.
   */
  login(username: string, password: string): Promise<void>;

  /**
   * Clear the in-memory private key and reset all auth state.
   *
   * Calls `ZkpAuthClient.clearKey()` then resets `user`, `isAuthenticated`,
   * and `error` to their initial values. `loading` is not mutated.
   */
  logout(): void;
}
