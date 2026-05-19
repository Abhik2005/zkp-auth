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
 *                    `null` immediately after `register()` (key stored,
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
   * Generates a random Ed25519 keypair, encrypts the private key with `pin`
   * using Argon2id + AES-256-GCM, and persists it in IndexedDB. The public
   * key is sent to the server — `pin` is never transmitted.
   *
   * @param username Non-empty string, ≤ 256 UTF-8 bytes.
   * @param pin      Non-empty string. Local-only; never sent to the server.
   */
  register(username: string, pin: string): Promise<void>;

  /**
   * Authenticate an already-registered user.
   *
   * Decrypts the local key using `pin`, computes a Schnorr ZKP proof, and
   * submits it to the server. The private key is zeroed immediately after
   * proof assembly.
   *
   * @param username Non-empty string, ≤ 256 UTF-8 bytes.
   * @param pin      The PIN used when `register()` was called on this device.
   */
  login(username: string, pin: string): Promise<void>;

  /**
   * Check whether an encrypted key exists in local storage for `userId`.
   *
   * Use this to decide whether to render a "Register" or "Log in with PIN"
   * form without making a network call.
   *
   * @param userId Username to check.
   */
  hasLocalKey(userId: string): Promise<boolean>;

  /**
   * Clear all auth state and reset to the unauthenticated initial state.
   *
   * Does NOT remove the encrypted key from IndexedDB — the user can log
   * back in on this device with their PIN.
   */
  logout(): void;
}
