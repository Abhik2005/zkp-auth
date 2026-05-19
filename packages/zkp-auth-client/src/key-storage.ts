// @zkp-auth/client — KeyStorage abstraction and IndexedDB implementation
//
// Architecture
// ─────────────────────────────────────────────────────────────────────────
// KeyStorage is a pluggable interface. Today it ships with two implementations:
//
//   IndexedDBKeyStorage  — production browser storage. Wraps the private key
//                          with Argon2id + AES-256-GCM and persists the
//                          encrypted record in IndexedDB.
//
//   MemoryKeyStorage     — in-process Map<string, …>. Intended for unit tests
//                          and server-side / Electron environments where IDB
//                          is unavailable.
//
// A WebAuthn-backed implementation (WebAuthnKeyStorage) can be added later
// by implementing the same KeyStorage interface — the ZkpAuthClient and the
// server protocol require zero changes.
//
// Wrapping key derivation
// ─────────────────────────────────────────────────────────────────────────
// PIN → Argon2id(pin, 16-byte salt, { t:3, m:65536, p:1 }) → 32-byte key
// Private key → AES-256-GCM(wrappingKey, privateKey, 12-byte IV) → ciphertext
//
// The PIN never leaves the device. The stored record contains only public or
// non-secret material: the random salt, IV, ciphertext, and the public key
// (which is already stored on the server). Even if IndexedDB is exfiltrated
// the attacker must brute-force the PIN through Argon2id's memory barrier.
//
// StoredKeyRecord (IndexedDB value schema)
// ─────────────────────────────────────────────────────────────────────────
// { version:1, pubKeyHex:string, saltB64:string, ivB64:string, ctB64:string }
//
// The same JSON shape is used as the portable backup blob returned by
// exportBlob() and consumed by importBlob().

import { argon2id } from '@noble/hashes/argon2.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToNumberLE } from '@noble/curves/utils.js';

import { ZkpCryptoError, ZkpStorageError } from './errors.js';
import { browserGenerateKeyPair } from './crypto.js';

// ── Argon2id parameters ──────────────────────────────────────────────────────

/**
 * Argon2id memory cost in KiB.
 *
 * Production: 65_536 KiB (64 MB) — OWASP 2023 recommendation.
 * Test builds inject `__TEST_ARGON2_MEMORY__ = 64` (64 KiB) via the
 * vitest `define` config so the suite stays fast without changing the
 * production default.
 */
const ARGON2_MEMORY_COST: number =
  typeof __TEST_ARGON2_MEMORY__ !== 'undefined' ? __TEST_ARGON2_MEMORY__ : 65_536;

/** Argon2id time cost (number of passes). */
const ARGON2_TIME_COST = 3;

/** Argon2id parallelism factor. */
const ARGON2_PARALLELISM = 1;

// ── IndexedDB constants ──────────────────────────────────────────────────────

const DB_NAME = 'zkp-auth-keys';
const DB_VERSION = 1;
const STORE_NAME = 'keys';

// ── Internal record schema ───────────────────────────────────────────────────

/**
 * Shape of the value persisted in IndexedDB and exported as a backup blob.
 * All binary fields are base64url-encoded strings.
 *
 * @internal
 */
interface StoredKeyRecord {
  /** Schema version — reserved for future migrations. */
  readonly version: 1;
  /** Hex-encoded 32-byte Ed25519 public key. Not secret; matches server. */
  readonly pubKeyHex: string;
  /** Base64url-encoded 16-byte Argon2id salt. */
  readonly saltB64: string;
  /** Base64url-encoded 12-byte AES-GCM nonce. */
  readonly ivB64: string;
  /** Base64url-encoded AES-GCM ciphertext (32-byte key + 16-byte auth tag = 48 bytes). */
  readonly ctB64: string;
}

// ── Base64url helpers ────────────────────────────────────────────────────────

/** Encode a Uint8Array to base64url (no padding). */
function toB64(bytes: Uint8Array): string {
  // btoa is available in all modern browsers and Node 16+.
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/** Decode a base64url string (with or without padding) to Uint8Array. */
function fromB64(b64: string): Uint8Array {
  const padded = b64.replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (padded.length % 4)) % 4;
  const binary = atob(padded + '='.repeat(padding));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

// ── Hex helpers ──────────────────────────────────────────────────────────────

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ── Argon2id + AES-GCM key wrapping ─────────────────────────────────────────

/**
 * Derive a 32-byte AES-256 wrapping key from a PIN and an Argon2id salt.
 *
 * @internal
 */
function deriveWrappingKey(pin: string, salt: Uint8Array): Uint8Array {
  return argon2id(new TextEncoder().encode(pin), salt, {
    t: ARGON2_TIME_COST,
    m: ARGON2_MEMORY_COST,
    p: ARGON2_PARALLELISM,
    dkLen: 32,
  });
}

/**
 * Wrap (encrypt) a 32-byte private key with a PIN.
 *
 * @returns A `StoredKeyRecord` ready for IndexedDB or blob export.
 * @internal
 */
async function wrapKey(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  pin: string,
): Promise<StoredKeyRecord> {
  // 1. Random Argon2id salt (16 bytes).
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));

  // 2. Derive wrapping key via Argon2id.
  const wrappingKeyBytes = deriveWrappingKey(pin, salt);

  // 3. Import the wrapping key as non-extractable AES-GCM CryptoKey.
  // WebCrypto subtle.importKey expects ArrayBuffer (not Uint8Array<ArrayBufferLike>),
  // so we slice to a guaranteed plain ArrayBuffer.
  const wrappingKey = await globalThis.crypto.subtle.importKey(
    'raw',
    wrappingKeyBytes.buffer.slice(
      wrappingKeyBytes.byteOffset,
      wrappingKeyBytes.byteOffset + wrappingKeyBytes.byteLength,
    ) as ArrayBuffer,
    'AES-GCM',
    false,
    ['encrypt'],
  );

  // 4. Random IV (12 bytes — GCM standard).
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ivBuffer = iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer;

  // 5. Encrypt the private key.
  const pkBuffer = privateKey.buffer.slice(
    privateKey.byteOffset,
    privateKey.byteOffset + privateKey.byteLength,
  ) as ArrayBuffer;
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivBuffer },
    wrappingKey,
    pkBuffer,
  );

  return {
    version: 1,
    pubKeyHex: toHex(publicKey),
    saltB64: toB64(salt),
    ivB64: toB64(iv),
    ctB64: toB64(new Uint8Array(ciphertext)),
  };
}

/**
 * Unwrap (decrypt) a stored key record with the user's PIN.
 *
 * @returns 32-byte private key. **Caller MUST zero this buffer after use.**
 * @throws ZkpCryptoError('DECRYPTION_FAILED') when the PIN is wrong or the
 *   record is corrupt (AES-GCM tag mismatch).
 * @internal
 */
async function unwrapKey(record: StoredKeyRecord, pin: string): Promise<Uint8Array> {
  const salt = fromB64(record.saltB64);
  const iv = fromB64(record.ivB64);
  const ct = fromB64(record.ctB64);

  // 1. Derive wrapping key from the same PIN + stored salt.
  const wrappingKeyBytes = deriveWrappingKey(pin, salt);

  // 2. Import as non-extractable AES-GCM CryptoKey for decryption.
  const wrappingKey = await globalThis.crypto.subtle.importKey(
    'raw',
    wrappingKeyBytes.buffer.slice(
      wrappingKeyBytes.byteOffset,
      wrappingKeyBytes.byteOffset + wrappingKeyBytes.byteLength,
    ) as ArrayBuffer,
    'AES-GCM',
    false,
    ['decrypt'],
  );

  // 3. Decrypt. AES-GCM verifies the authentication tag; if the PIN is wrong
  //    the tag will not match and subtle.decrypt() rejects.
  const ivBuffer = iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer;
  const ctBuffer = ct.buffer.slice(ct.byteOffset, ct.byteOffset + ct.byteLength) as ArrayBuffer;
  let plaintext: ArrayBuffer;
  try {
    plaintext = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBuffer },
      wrappingKey,
      ctBuffer,
    );
  } catch (cause: unknown) {
    throw new ZkpCryptoError(
      'DECRYPTION_FAILED',
      'Wrong PIN or corrupt key record — AES-GCM authentication failed',
      { cause },
    );
  }

  return new Uint8Array(plaintext);
}

// ── Public interface ─────────────────────────────────────────────────────────

/**
 * Pluggable key-storage backend for `ZkpAuthClient`.
 *
 * Implement this interface to swap in a WebAuthn / platform-authenticator
 * backend later without changing any ZKP protocol or server code.
 *
 * ## Implementor contract
 *
 * - `generateAndStore` MUST generate a cryptographically random Ed25519
 *   scalar, protect it with the backend's mechanism, and return its
 *   corresponding public key.
 * - `unlock` MUST return the raw 32-byte private key scalar. The caller
 *   (always `ZkpAuthClient`) zeros the buffer in a `finally` block after
 *   proof computation. Implementors MUST NOT cache the plain private key.
 * - All methods MUST throw typed errors from `@zkp-auth/client/errors`:
 *   `ZkpStorageError('STORAGE_ERROR')`, `ZkpStorageError('KEY_NOT_FOUND')`,
 *   or `ZkpCryptoError('DECRYPTION_FAILED')`.
 */
export interface KeyStorage {
  /**
   * Returns `true` if an encrypted key exists for `userId`.
   * Does **not** require the PIN.
   */
  hasKey(userId: string): Promise<boolean>;

  /**
   * Generate a fresh random Ed25519 keypair, protect it with `pin`, and
   * persist it under `userId`.
   *
   * @returns 32-byte Ed25519 public key bytes (not secret; sent to server).
   * @throws ZkpStorageError('STORAGE_ERROR') on backend write failure.
   */
  generateAndStore(userId: string, pin: string): Promise<Uint8Array>;

  /**
   * Decrypt and return the private key for `userId`.
   *
   * **Caller MUST zero the returned buffer after use.** `ZkpAuthClient`
   * does this unconditionally in a `finally` block.
   *
   * @throws ZkpStorageError('KEY_NOT_FOUND')      — no key stored for `userId`.
   * @throws ZkpCryptoError('DECRYPTION_FAILED')   — wrong PIN or corrupt record.
   * @throws ZkpStorageError('STORAGE_ERROR')       — backend read failure.
   */
  unlock(userId: string, pin: string): Promise<Uint8Array>;

  /**
   * Export a PIN-encrypted backup blob (JSON string, base64url-encoded fields).
   *
   * The blob contains the same encryption as the stored record, so the user
   * needs the same PIN to import it on another device.
   *
   * @throws ZkpStorageError('KEY_NOT_FOUND') — no key stored for `userId`.
   * @throws ZkpStorageError('STORAGE_ERROR') — backend read failure.
   */
  exportBlob(userId: string, pin: string): Promise<string>;

  /**
   * Import a key from a backup blob produced by `exportBlob`.
   *
   * Validates the PIN is correct (by decrypting the blob), then re-encrypts
   * with a fresh salt/IV and stores it in this backend.
   *
   * @throws ZkpCryptoError('DECRYPTION_FAILED') — wrong PIN for the blob.
   * @throws ZkpStorageError('STORAGE_ERROR')     — backend write failure.
   */
  importBlob(userId: string, blob: string, pin: string): Promise<void>;

  /**
   * Permanently delete the stored key for `userId`.
   *
   * Idempotent — does not throw if no key exists.
   *
   * @throws ZkpStorageError('STORAGE_ERROR') on backend failure.
   */
  deleteKey(userId: string): Promise<void>;
}

// ── IndexedDB implementation ─────────────────────────────────────────────────

/**
 * Open (or upgrade) the IndexedDB database for key storage.
 *
 * @internal
 */
function openDb(idbFactory: IDBFactory): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = idbFactory.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };

    req.onsuccess = () => { resolve(req.result); };
    req.onerror = () => {
      reject(new Error(`IndexedDB open failed: ${req.error?.message ?? 'unknown'}`));
    };
  });
}

/**
 * Run an IndexedDB transaction and return the result of `operate`.
 *
 * @internal
 */
function idbTransaction<T>(
  db: IDBDatabase,
  mode: IDBTransactionMode,
  operate: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, mode);
    const store = tx.objectStore(STORE_NAME);
    const req = operate(store);
    req.onsuccess = () => { resolve(req.result as T); };
    req.onerror = () => { reject(req.error); };
    tx.onerror = () => { reject(tx.error); };
  });
}

/**
 * Browser-native `KeyStorage` implementation backed by IndexedDB.
 *
 * Private keys are never stored in plaintext. Each key is wrapped with
 * AES-256-GCM using a wrapping key derived from the user's PIN via
 * Argon2id (64 MB memory cost, 3 passes). The stored record contains
 * only the Argon2id salt, AES-GCM IV, ciphertext, and the public key
 * (which is already public knowledge — it lives on the server too).
 *
 * ## WebAuthn upgrade path
 *
 * Replace `new IndexedDBKeyStorage()` in `ZkpAuthClient` with a
 * `WebAuthnKeyStorage` instance that implements {@link KeyStorage}. No
 * other code changes required.
 *
 * @example
 * ```ts
 * const client = new ZkpAuthClient({
 *   baseUrl: 'https://api.example.com',
 *   storage: new IndexedDBKeyStorage(),
 * });
 * ```
 */
export class IndexedDBKeyStorage implements KeyStorage {
  /**
   * @param idbFactory Optional IDBFactory override. Defaults to
   *   `globalThis.indexedDB`. Inject `fake-indexeddb`'s IDBFactory in tests.
   */
  constructor(private readonly idbFactory: IDBFactory = globalThis.indexedDB) {}

  // ── Helpers ──────────────────────────────────────────────────────────────

  /** Open the DB and wrap any IDB error in ZkpStorageError. */
  private async db(): Promise<IDBDatabase> {
    try {
      return await openDb(this.idbFactory);
    } catch (cause: unknown) {
      throw new ZkpStorageError('STORAGE_ERROR', 'Failed to open IndexedDB', { cause });
    }
  }

  /** Read a stored record. Returns `null` when the key is missing. */
  private async readRecord(userId: string): Promise<StoredKeyRecord | null> {
    const db = await this.db();
    try {
      const result = await idbTransaction<StoredKeyRecord | undefined>(
        db,
        'readonly',
        (store) => store.get(userId) as IDBRequest<StoredKeyRecord | undefined>,
      );
      return result ?? null;
    } catch (cause: unknown) {
      throw new ZkpStorageError('STORAGE_ERROR', `IndexedDB read failed for "${userId}"`, { cause });
    } finally {
      db.close();
    }
  }

  /** Write a stored record, overwriting any existing entry. */
  private async writeRecord(userId: string, record: StoredKeyRecord): Promise<void> {
    const db = await this.db();
    try {
      await idbTransaction<IDBValidKey>(db, 'readwrite', (store) => store.put(record, userId));
    } catch (cause: unknown) {
      throw new ZkpStorageError('STORAGE_ERROR', `IndexedDB write failed for "${userId}"`, { cause });
    } finally {
      db.close();
    }
  }

  // ── KeyStorage interface ──────────────────────────────────────────────────

  /** @inheritDoc */
  async hasKey(userId: string): Promise<boolean> {
    const record = await this.readRecord(userId);
    return record !== null;
  }

  /** @inheritDoc */
  async generateAndStore(userId: string, pin: string): Promise<Uint8Array> {
    const { privateKey, publicKey } = browserGenerateKeyPair();
    try {
      const record = await wrapKey(privateKey, publicKey, pin);
      await this.writeRecord(userId, record);
      return publicKey;
    } finally {
      // Best-effort zeroize. The GC may have already moved the backing buffer.
      privateKey.fill(0);
    }
  }

  /** @inheritDoc */
  async unlock(userId: string, pin: string): Promise<Uint8Array> {
    const record = await this.readRecord(userId);
    if (record === null) {
      throw new ZkpStorageError(
        'KEY_NOT_FOUND',
        `No key stored for user "${userId}". Register on this device first.`,
      );
    }
    // throws ZkpCryptoError('DECRYPTION_FAILED') on wrong PIN
    return unwrapKey(record, pin);
  }

  /** @inheritDoc */
  async exportBlob(userId: string, _pin: string): Promise<string> {
    const record = await this.readRecord(userId);
    if (record === null) {
      throw new ZkpStorageError(
        'KEY_NOT_FOUND',
        `No key stored for user "${userId}".`,
      );
    }
    // The record itself is the blob — it's already PIN-encrypted.
    return JSON.stringify(record);
  }

  /** @inheritDoc */
  async importBlob(userId: string, blob: string, pin: string): Promise<void> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(blob) as unknown;
    } catch (cause: unknown) {
      throw new ZkpStorageError('STORAGE_ERROR', 'Backup blob is not valid JSON', { cause });
    }

    if (!isStoredKeyRecord(parsed)) {
      throw new ZkpStorageError('STORAGE_ERROR', 'Backup blob has an unexpected shape');
    }

    // Validate the PIN is correct before storing (throws DECRYPTION_FAILED on wrong PIN).
    const privateKey = await unwrapKey(parsed, pin);

    // Re-encrypt with a fresh salt + IV for this device, then store.
    const pubKeyBytes = fromB64(parsed.pubKeyHex.length === 64
      ? btoa(String.fromCharCode(...parsed.pubKeyHex.match(/.{2}/g)!.map((h) => parseInt(h, 16))))
      : parsed.pubKeyHex); // fallback: handle if pubKeyHex is already base64 somehow

    // Derive public key directly from the private key scalar to be safe.
    const scalar = bytesToNumberLE(privateKey);
    if (scalar === 0n || scalar >= ed25519.Point.Fn.ORDER) {
      privateKey.fill(0);
      throw new ZkpCryptoError('CURVE_ERROR', 'Backup blob contains an invalid private key scalar');
    }
    const publicKeyBytes = ed25519.Point.BASE.multiply(scalar).toBytes();
    void pubKeyBytes; // The stored pubKeyHex is informational; we re-derive for correctness.

    try {
      const freshRecord = await wrapKey(privateKey, publicKeyBytes, pin);
      await this.writeRecord(userId, freshRecord);
    } finally {
      privateKey.fill(0);
    }
  }

  /** @inheritDoc */
  async deleteKey(userId: string): Promise<void> {
    const db = await this.db();
    try {
      await idbTransaction<undefined>(db, 'readwrite', (store) => store.delete(userId) as IDBRequest<undefined>);
    } catch (cause: unknown) {
      throw new ZkpStorageError('STORAGE_ERROR', `IndexedDB delete failed for "${userId}"`, { cause });
    } finally {
      db.close();
    }
  }
}

// ── Type guard ───────────────────────────────────────────────────────────────

function isStoredKeyRecord(value: unknown): value is StoredKeyRecord {
  if (typeof value !== 'object' || value === null) return false;
  const r = value as Record<string, unknown>;
  return (
    r['version'] === 1 &&
    typeof r['pubKeyHex'] === 'string' &&
    typeof r['saltB64'] === 'string' &&
    typeof r['ivB64'] === 'string' &&
    typeof r['ctB64'] === 'string'
  );
}

// ── MemoryKeyStorage ─────────────────────────────────────────────────────────

/**
 * In-process `KeyStorage` implementation backed by a plain `Map`.
 *
 * Suitable for:
 * - Unit and integration tests (no IndexedDB required).
 * - Server-side / Electron environments without browser IDB.
 * - Prototyping.
 *
 * **Not suitable for production browser use** — data is lost on page reload.
 *
 * @example
 * ```ts
 * // In tests:
 * const storage = new MemoryKeyStorage();
 * const client = new ZkpAuthClient({ baseUrl: '...', storage });
 * ```
 */
export class MemoryKeyStorage implements KeyStorage {
  private readonly store = new Map<string, StoredKeyRecord>();

  /** @inheritDoc */
  async hasKey(userId: string): Promise<boolean> {
    return this.store.has(userId);
  }

  /** @inheritDoc */
  async generateAndStore(userId: string, pin: string): Promise<Uint8Array> {
    const { privateKey, publicKey } = browserGenerateKeyPair();
    try {
      const record = await wrapKey(privateKey, publicKey, pin);
      this.store.set(userId, record);
      return publicKey;
    } finally {
      privateKey.fill(0);
    }
  }

  /** @inheritDoc */
  async unlock(userId: string, pin: string): Promise<Uint8Array> {
    const record = this.store.get(userId);
    if (record === undefined) {
      throw new ZkpStorageError(
        'KEY_NOT_FOUND',
        `No key stored for user "${userId}". Register first.`,
      );
    }
    return unwrapKey(record, pin);
  }

  /** @inheritDoc */
  async exportBlob(userId: string, _pin: string): Promise<string> {
    const record = this.store.get(userId);
    if (record === undefined) {
      throw new ZkpStorageError('KEY_NOT_FOUND', `No key stored for user "${userId}".`);
    }
    return JSON.stringify(record);
  }

  /** @inheritDoc */
  async importBlob(userId: string, blob: string, pin: string): Promise<void> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(blob) as unknown;
    } catch (cause: unknown) {
      throw new ZkpStorageError('STORAGE_ERROR', 'Backup blob is not valid JSON', { cause });
    }

    if (!isStoredKeyRecord(parsed)) {
      throw new ZkpStorageError('STORAGE_ERROR', 'Backup blob has an unexpected shape');
    }

    // Validate PIN by decrypting (throws DECRYPTION_FAILED on wrong PIN).
    const privateKey = await unwrapKey(parsed, pin);

    // Re-derive public key from the scalar.
    const scalar = bytesToNumberLE(privateKey);
    if (scalar === 0n || scalar >= ed25519.Point.Fn.ORDER) {
      privateKey.fill(0);
      throw new ZkpCryptoError('CURVE_ERROR', 'Backup blob contains an invalid private key scalar');
    }
    const publicKeyBytes = ed25519.Point.BASE.multiply(scalar).toBytes();

    try {
      const freshRecord = await wrapKey(privateKey, publicKeyBytes, pin);
      this.store.set(userId, freshRecord);
    } finally {
      privateKey.fill(0);
    }
  }

  /** @inheritDoc */
  async deleteKey(userId: string): Promise<void> {
    this.store.delete(userId);
  }

  /**
   * Clear all stored keys.
   *
   * Convenience method for resetting state between tests.
   */
  clear(): void {
    this.store.clear();
  }
}
