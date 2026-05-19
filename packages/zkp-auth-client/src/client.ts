// @zkp-auth/client — ZkpAuthClient: the single developer-facing class
//
// Authentication flow:
//
//   client.register(username, pin)
//     → generate random Ed25519 keypair
//     → encrypt private key with PIN via KeyStorage (Argon2id + AES-256-GCM)
//     → store encrypted blob in IndexedDB (or active storage backend)
//     → POST { userId, publicKeyHex } to /auth/register
//     → return { userId, publicKeyHex }
//
//   client.login(username, pin)
//     → decrypt private key from KeyStorage
//     → POST { userId } to /auth/challenge → 32-byte challenge
//     → compute 64-byte Schnorr proof in memory
//     → zero private key immediately after proof is assembled
//     → POST { userId, proofHex } to /auth/verify
//     → return { userId, token }
//
// The private key lives in memory ONLY between KeyStorage.unlock() and the
// finally block in login(). It is never cached, never serialised, and is
// zeroed unconditionally — even when verify fails.
//
// WebAuthn upgrade path:
//   Pass a WebAuthnKeyStorage (implements KeyStorage) to the constructor.
//   No other code changes required anywhere.

import {
  browserComputeProof,
  validateUsername,
  validatePin,
} from './crypto.js';

import {
  postRegister,
  postChallenge,
  postVerify,
  bytesToHex,
  hexToBytes,
} from './http.js';

import { ZkpCryptoError } from './errors.js';
import { IndexedDBKeyStorage, type KeyStorage } from './key-storage.js';

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

  /**
   * Key-storage backend. Defaults to `IndexedDBKeyStorage`.
   *
   * Swap in a `MemoryKeyStorage` (from `@zkp-auth/client`) for tests, or a
   * future `WebAuthnKeyStorage` for hardware-backed security. The ZKP
   * protocol and server code require no changes.
   *
   * @example
   * ```ts
   * import { MemoryKeyStorage } from '@zkp-auth/client';
   * const client = new ZkpAuthClient({ baseUrl: '...', storage: new MemoryKeyStorage() });
   * ```
   */
  storage?: KeyStorage;
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
 * Create one instance per application and reuse it across `register` /
 * `login` calls. The instance holds no private key material at rest —
 * the private key is decrypted from storage only for the duration of
 * proof computation and zeroed immediately after.
 *
 * @example
 * ```ts
 * const client = new ZkpAuthClient({ baseUrl: 'https://api.example.com' });
 *
 * // First visit: register (generates a random key, protected by PIN)
 * await client.register('alice', '123456');
 *
 * // Immediately log in
 * const { token } = await client.login('alice', '123456');
 *
 * // Subsequent visits: just log in with PIN (key is in IndexedDB)
 * const { token } = await client.login('alice', '123456');
 *
 * // Check whether a key is already stored (to decide register vs login UI)
 * if (await client.hasLocalKey('alice')) { ... }
 *
 * // Backup / device transfer
 * const blob = await client.exportKeyBlob('alice', '123456');
 * // ... send blob to new device ...
 * await client.importKeyBlob('alice', blob, '123456');
 * ```
 */
export class ZkpAuthClient {
  private readonly baseUrl: string;
  private readonly storage: KeyStorage;

  /**
   * In-memory private key — populated only by the legacy `loadKey()` API.
   * Normal `register` / `login` flows do NOT use this field; the key lives
   * only in the local stack of `login()` for the duration of proof assembly.
   */
  private _privateKey: Uint8Array | null = null;

  /**
   * @param options `ZkpAuthClientOptions` — requires `baseUrl`.
   */
  constructor(options: ZkpAuthClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.storage = options.storage ?? new IndexedDBKeyStorage();
  }

  // ── Storage-level helpers ────────────────────────────────────────────────────

  /**
   * Returns `true` when an encrypted key exists in storage for `userId`.
   *
   * Use this to decide whether to show a "Register" or "Log in with PIN" UI
   * without making a network call.
   *
   * @param userId The username to check.
   */
  async hasLocalKey(userId: string): Promise<boolean> {
    return this.storage.hasKey(userId);
  }

  /**
   * Export an encrypted backup blob for `userId`.
   *
   * The blob is a JSON string containing the PIN-encrypted private key.
   * Pass it to `importKeyBlob` on another device to transfer the identity.
   *
   * @param userId Username whose key to export.
   * @param pin    The PIN that protects the key in storage.
   *
   * @throws ZkpStorageError('KEY_NOT_FOUND') — no key stored for `userId`.
   */
  async exportKeyBlob(userId: string, pin: string): Promise<string> {
    validateUsername(userId);
    validatePin(pin);
    return this.storage.exportBlob(userId, pin);
  }

  /**
   * Import a key backup blob onto this device.
   *
   * After import, `login(userId, pin)` works on this device without
   * re-registering with the server.
   *
   * @param userId Username to import the key under.
   * @param blob   JSON blob produced by `exportKeyBlob`.
   * @param pin    The PIN used when the blob was exported.
   *
   * @throws ZkpCryptoError('DECRYPTION_FAILED') — wrong PIN for the blob.
   * @throws ZkpStorageError('STORAGE_ERROR')     — blob is malformed.
   */
  async importKeyBlob(userId: string, blob: string, pin: string): Promise<void> {
    validateUsername(userId);
    validatePin(pin);
    await this.storage.importBlob(userId, blob, pin);
  }

  // ── Legacy in-memory key API ─────────────────────────────────────────────────
  //
  // These methods are retained for advanced / low-level use cases (e.g. Electron
  // apps managing keys outside IndexedDB). Normal applications should use
  // register() / login() / exportKeyBlob() / importKeyBlob() instead.

  /**
   * `true` when a private key is held in memory via the legacy `loadKey()` API.
   *
   * This is `false` after `register()` and `login()` — those flows zero the
   * key immediately after proof assembly.
   */
  get hasKey(): boolean {
    return this._privateKey !== null;
  }

  /**
   * Zero-fill and discard any private key held in memory.
   *
   * This does NOT remove the encrypted key from IndexedDB storage. To revoke
   * a key entirely, call `storage.deleteKey(userId)` directly.
   */
  clearKey(): void {
    if (this._privateKey !== null) {
      this._privateKey.fill(0);
      this._privateKey = null;
    }
  }

  /**
   * Load a raw private key into memory.
   *
   * Advanced API — prefer `login()` for normal flows. Use this when
   * importing a key from an out-of-band channel (e.g. a QR transfer).
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
    this._privateKey = Uint8Array.from(privateKey);
  }

  /**
   * Export a copy of the private key currently held in memory.
   *
   * Only works after `loadKey()`. Normal `register` / `login` flows do not
   * retain the key in memory.
   *
   * @returns A 32-byte copy of the in-memory private key.
   * @throws ZkpCryptoError('CURVE_ERROR') when no key is in memory.
   */
  exportKey(): Uint8Array {
    if (this._privateKey === null) {
      throw new ZkpCryptoError(
        'CURVE_ERROR',
        'exportKey: no private key in memory — call loadKey() first',
      );
    }
    return Uint8Array.from(this._privateKey);
  }

  // ── Protocol methods ─────────────────────────────────────────────────────────

  /**
   * Register a new user with the ZKP auth server.
   *
   * Steps:
   * 1. Validate `username` and `pin`.
   * 2. Generate a truly random Ed25519 keypair via the browser CSPRNG.
   * 3. Encrypt the private key with `pin` (Argon2id + AES-256-GCM) and
   *    persist the encrypted blob in IndexedDB under `username`.
   * 4. POST `{ userId: username, publicKeyHex }` to `/auth/register`.
   * 5. Return `{ userId, publicKeyHex }`.
   *
   * The private key never appears in memory after this call returns. It
   * is zeroed inside the storage backend immediately after encryption.
   *
   * @param username Non-empty string, ≤ 256 UTF-8 bytes.
   * @param pin      Non-empty string. Local only — never sent to the server.
   *
   * @throws ZkpCryptoError('INVALID_USERNAME') — empty or oversize username.
   * @throws ZkpCryptoError('INVALID_PIN')      — empty PIN.
   * @throws ZkpCryptoError('RNG_FAILURE')      — CSPRNG or rejection-sampling failure.
   * @throws ZkpCryptoError('CURVE_ERROR')      — @noble/curves internal error.
   * @throws ZkpStorageError('STORAGE_ERROR')   — IndexedDB write failed.
   * @throws ZkpNetworkError                    — fetch() rejected.
   * @throws ZkpServerError('REGISTER_FAILED')  — server returned non-2xx.
   */
  async register(username: string, pin: string): Promise<RegisterOutcome> {
    // Step 1 — validate inputs.
    validateUsername(username);
    validatePin(pin);

    // Step 2+3 — generate random keypair and store it encrypted.
    // Returns only the public key; private key is zeroed inside the backend.
    const publicKey = await this.storage.generateAndStore(username, pin);
    const publicKeyHex = bytesToHex(publicKey);

    // Step 4 — register with the server.
    // If this throws, the key is already in local storage. The user can retry
    // registration or call storage.deleteKey(username) to clean up.
    await postRegister(this.baseUrl, username, publicKeyHex);

    return { userId: username, publicKeyHex };
  }

  /**
   * Authenticate an already-registered user and obtain a JWT.
   *
   * Steps:
   * 1. Validate `username` and `pin`.
   * 2. Decrypt the private key from local storage using `pin`.
   * 3. POST `{ userId: username }` to `/auth/challenge` → 32-byte challenge.
   * 4. Compute a 64-byte Schnorr proof using the private key.
   * 5. Zero the private key unconditionally.
   * 6. POST `{ userId: username, proofHex }` to `/auth/verify`.
   * 7. Return `{ userId, token }`.
   *
   * The private key is in memory only between steps 2 and 5.
   *
   * @param username Non-empty string, ≤ 256 UTF-8 bytes.
   * @param pin      The PIN used when `register()` was called on this device.
   *
   * @throws ZkpCryptoError('INVALID_USERNAME')  — empty or oversize username.
   * @throws ZkpCryptoError('INVALID_PIN')       — empty PIN.
   * @throws ZkpStorageError('KEY_NOT_FOUND')    — no key in storage; register first.
   * @throws ZkpCryptoError('DECRYPTION_FAILED') — wrong PIN.
   * @throws ZkpStorageError('STORAGE_ERROR')    — IndexedDB read failed.
   * @throws ZkpCryptoError('CURVE_ERROR')       — @noble/curves internal error.
   * @throws ZkpCryptoError('RNG_FAILURE')       — CSPRNG failure during nonce generation.
   * @throws ZkpNetworkError                     — fetch() rejected.
   * @throws ZkpServerError('CHALLENGE_FAILED')  — server did not issue a challenge.
   * @throws ZkpServerError('PROOF_REJECTED')    — proof verification failed.
   * @throws ZkpServerError('SERVER_ERROR')      — unexpected server fault.
   */
  async login(username: string, pin: string): Promise<LoginOutcome> {
    // Step 1 — validate inputs.
    validateUsername(username);
    validatePin(pin);

    // Step 2 — decrypt private key from storage.
    // Throws KEY_NOT_FOUND or DECRYPTION_FAILED on failure.
    const privateKey = await this.storage.unlock(username, pin);

    try {
      // Step 3 — fetch challenge.
      const challengeResult = await postChallenge(this.baseUrl, username);
      const challengeBytes = hexToBytes(challengeResult.challengeHex);

      if (challengeBytes.byteLength !== 32) {
        throw new ZkpCryptoError(
          'CURVE_ERROR',
          `Server returned a challenge of unexpected length: expected 32 bytes, got ${challengeBytes.byteLength.toString()}`,
        );
      }

      // Step 4 — compute Schnorr proof.
      const proof = browserComputeProof(privateKey, challengeBytes);
      const proofHex = bytesToHex(proof);

      // Step 6 — submit proof.
      const verifyResult = await postVerify(this.baseUrl, username, proofHex);

      return { userId: username, token: verifyResult.token ?? '' };
    } finally {
      // Step 5 — zero the private key unconditionally, even on error.
      privateKey.fill(0);
    }
  }
}
