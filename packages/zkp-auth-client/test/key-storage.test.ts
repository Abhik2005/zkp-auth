// tests/key-storage.test.ts — unit tests for KeyStorage implementations
//
// Tier: Unit
// Covers: MemoryKeyStorage (full), IndexedDBKeyStorage (via fake-indexeddb)
//         wrapKey / unwrapKey flow (indirectly through generateAndStore / unlock)
// Environment: jsdom + fake-indexeddb

import { describe, it, expect, beforeEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import { IndexedDBKeyStorage, MemoryKeyStorage } from '../src/key-storage.js';
import { ZkpCryptoError, ZkpStorageError } from '../src/errors.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToNumberLE } from '@noble/curves/utils.js';

// ── Shared behaviour contract ─────────────────────────────────────────────────
//
// Both MemoryKeyStorage and IndexedDBKeyStorage implement the same interface.
// We define a shared test suite as a function and call it for each backend.

function runKeyStorageContract(
  label: string,
  makeStorage: () => MemoryKeyStorage | IndexedDBKeyStorage,
): void {
  describe(`${label} — KeyStorage contract`, () => {
    let storage: MemoryKeyStorage | IndexedDBKeyStorage;
    const USER = 'alice';
    const PIN = '1234';

    beforeEach(() => {
      storage = makeStorage();
    });

    // ── hasKey ───────────────────────────────────────────────────────────────

    describe('hasKey()', () => {
      it('returns false before any key is stored', async () => {
        expect(await storage.hasKey(USER)).toBe(false);
      });

      it('returns true after generateAndStore', async () => {
        await storage.generateAndStore(USER, PIN);
        expect(await storage.hasKey(USER)).toBe(true);
      });

      it('returns false for a different userId', async () => {
        await storage.generateAndStore(USER, PIN);
        expect(await storage.hasKey('bob')).toBe(false);
      });

      it('returns false after deleteKey', async () => {
        await storage.generateAndStore(USER, PIN);
        await storage.deleteKey(USER);
        expect(await storage.hasKey(USER)).toBe(false);
      });
    });

    // ── generateAndStore ──────────────────────────────────────────────────────

    describe('generateAndStore()', () => {
      it('returns a 32-byte Uint8Array (public key)', async () => {
        const pubKey = await storage.generateAndStore(USER, PIN);
        expect(pubKey).toBeInstanceOf(Uint8Array);
        expect(pubKey.byteLength).toBe(32);
      });

      it('returned publicKey is a valid Ed25519 point', async () => {
        const pubKey = await storage.generateAndStore(USER, PIN);
        expect(() => ed25519.Point.fromBytes(pubKey)).not.toThrow();
      });

      it('two calls produce different public keys (random keypair)', async () => {
        const pk1 = await storage.generateAndStore(USER, PIN);
        await storage.deleteKey(USER);
        const pk2 = await storage.generateAndStore(USER, PIN);
        expect(Buffer.from(pk1).equals(Buffer.from(pk2))).toBe(false);
      });

      it('publicKey matches unlock()→private key scalar · G', async () => {
        const pubKey = await storage.generateAndStore(USER, PIN);
        const privateKey = await storage.unlock(USER, PIN);
        const scalar = bytesToNumberLE(privateKey);
        const expected = ed25519.Point.BASE.multiply(scalar).toBytes();
        expect(Buffer.from(pubKey).equals(Buffer.from(expected))).toBe(true);
        privateKey.fill(0);
      });
    });

    // ── unlock ────────────────────────────────────────────────────────────────

    describe('unlock()', () => {
      beforeEach(async () => {
        await storage.generateAndStore(USER, PIN);
      });

      it('returns a 32-byte Uint8Array (private key)', async () => {
        const pk = await storage.unlock(USER, PIN);
        expect(pk).toBeInstanceOf(Uint8Array);
        expect(pk.byteLength).toBe(32);
        pk.fill(0);
      });

      it('returned private key scalar is in [1, L)', async () => {
        const pk = await storage.unlock(USER, PIN);
        const n = bytesToNumberLE(pk);
        expect(n >= 1n).toBe(true);
        expect(n < ed25519.Point.Fn.ORDER).toBe(true);
        pk.fill(0);
      });

      it('unlocking twice returns equal private keys', async () => {
        const pk1 = await storage.unlock(USER, PIN);
        const pk2 = await storage.unlock(USER, PIN);
        expect(Buffer.from(pk1).equals(Buffer.from(pk2))).toBe(true);
        pk1.fill(0);
        pk2.fill(0);
      });

      it('throws ZkpCryptoError(DECRYPTION_FAILED) on wrong PIN', async () => {
        await expect(storage.unlock(USER, 'wrongpin')).rejects.toThrow(ZkpCryptoError);
        try {
          await storage.unlock(USER, 'wrongpin');
        } catch (e) {
          expect((e as ZkpCryptoError).code).toBe('DECRYPTION_FAILED');
        }
      });

      it('throws ZkpStorageError(KEY_NOT_FOUND) when no key exists', async () => {
        await expect(storage.unlock('nobody', PIN)).rejects.toThrow(ZkpStorageError);
        try {
          await storage.unlock('nobody', PIN);
        } catch (e) {
          expect((e as ZkpStorageError).code).toBe('KEY_NOT_FOUND');
        }
      });

      it('returned buffer is independent (zeroing it does not affect the stored key)', async () => {
        const pk1 = await storage.unlock(USER, PIN);
        pk1.fill(0);
        // The stored key is unaffected — we can still unlock.
        const pk2 = await storage.unlock(USER, PIN);
        const n = bytesToNumberLE(pk2);
        expect(n >= 1n).toBe(true);
        pk2.fill(0);
      });
    });

    // ── exportBlob / importBlob ───────────────────────────────────────────────

    describe('exportBlob() / importBlob()', () => {
      let blob: string;
      let pubKey: Uint8Array;

      beforeEach(async () => {
        pubKey = await storage.generateAndStore(USER, PIN);
        blob = await storage.exportBlob(USER, PIN);
      });

      it('exportBlob returns a valid JSON string', () => {
        expect(typeof blob).toBe('string');
        expect(() => JSON.parse(blob)).not.toThrow();
      });

      it('exportBlob JSON has expected shape', () => {
        const parsed = JSON.parse(blob) as Record<string, unknown>;
        expect(parsed['version']).toBe(1);
        expect(typeof parsed['pubKeyHex']).toBe('string');
        expect(typeof parsed['saltB64']).toBe('string');
        expect(typeof parsed['ivB64']).toBe('string');
        expect(typeof parsed['ctB64']).toBe('string');
      });

      it('exportBlob throws KEY_NOT_FOUND when no key exists', async () => {
        await expect(storage.exportBlob('nobody', PIN)).rejects.toThrow(ZkpStorageError);
        try {
          await storage.exportBlob('nobody', PIN);
        } catch (e) {
          expect((e as ZkpStorageError).code).toBe('KEY_NOT_FOUND');
        }
      });

      it('importBlob restores the key to a fresh storage', async () => {
        const fresh = makeStorage();
        await fresh.importBlob(USER, blob, PIN);
        expect(await fresh.hasKey(USER)).toBe(true);
      });

      it('imported key unlocks with the same PIN', async () => {
        const fresh = makeStorage();
        await fresh.importBlob(USER, blob, PIN);
        const pk = await fresh.unlock(USER, PIN);
        expect(pk.byteLength).toBe(32);
        pk.fill(0);
      });

      it('imported key produces the same public key as the original', async () => {
        const fresh = makeStorage();
        await fresh.importBlob(USER, blob, PIN);
        const pk = await fresh.unlock(USER, PIN);
        const scalar = bytesToNumberLE(pk);
        const derivedPub = ed25519.Point.BASE.multiply(scalar).toBytes();
        expect(Buffer.from(derivedPub).equals(Buffer.from(pubKey))).toBe(true);
        pk.fill(0);
      });

      it('importBlob with wrong PIN throws DECRYPTION_FAILED', async () => {
        const fresh = makeStorage();
        await expect(fresh.importBlob(USER, blob, 'wrongpin')).rejects.toThrow(ZkpCryptoError);
        try {
          await fresh.importBlob(USER, blob, 'wrongpin');
        } catch (e) {
          expect((e as ZkpCryptoError).code).toBe('DECRYPTION_FAILED');
        }
      });

      it('importBlob with malformed JSON throws STORAGE_ERROR', async () => {
        const fresh = makeStorage();
        await expect(fresh.importBlob(USER, 'not-json', PIN)).rejects.toThrow(ZkpStorageError);
        try {
          await fresh.importBlob(USER, 'not-json', PIN);
        } catch (e) {
          expect((e as ZkpStorageError).code).toBe('STORAGE_ERROR');
        }
      });

      it('importBlob with valid JSON but wrong shape throws STORAGE_ERROR', async () => {
        const fresh = makeStorage();
        const bad = JSON.stringify({ version: 1, foo: 'bar' });
        await expect(fresh.importBlob(USER, bad, PIN)).rejects.toThrow(ZkpStorageError);
        try {
          await fresh.importBlob(USER, bad, PIN);
        } catch (e) {
          expect((e as ZkpStorageError).code).toBe('STORAGE_ERROR');
        }
      });
    });

    // ── deleteKey ─────────────────────────────────────────────────────────────

    describe('deleteKey()', () => {
      it('is idempotent — does not throw when no key exists', async () => {
        await expect(storage.deleteKey('nobody')).resolves.not.toThrow();
      });

      it('removes the key so unlock throws KEY_NOT_FOUND', async () => {
        await storage.generateAndStore(USER, PIN);
        await storage.deleteKey(USER);
        await expect(storage.unlock(USER, PIN)).rejects.toThrow(ZkpStorageError);
        try {
          await storage.unlock(USER, PIN);
        } catch (e) {
          expect((e as ZkpStorageError).code).toBe('KEY_NOT_FOUND');
        }
      });
    });

    // ── Security properties ───────────────────────────────────────────────────

    describe('Security — PIN isolation', () => {
      it('a different PIN produces distinct ciphertext (new salt each generateAndStore)', async () => {
        const blob1 = await (async () => {
          await storage.generateAndStore(USER, '0000');
          const b = await storage.exportBlob(USER, '0000');
          await storage.deleteKey(USER);
          return b;
        })();
        const blob2 = await (async () => {
          await storage.generateAndStore(USER, '1111');
          return storage.exportBlob(USER, '1111');
        })();
        // Different salts → different ciphertexts even for any key material.
        expect(blob1).not.toBe(blob2);
      });

      it('two generateAndStore calls produce different salts (fresh random IV)', async () => {
        await storage.generateAndStore(USER, PIN);
        const b1 = await storage.exportBlob(USER, PIN);
        await storage.deleteKey(USER);
        await storage.generateAndStore(USER, PIN);
        const b2 = await storage.exportBlob(USER, PIN);
        const r1 = JSON.parse(b1) as { saltB64: string };
        const r2 = JSON.parse(b2) as { saltB64: string };
        expect(r1.saltB64).not.toBe(r2.saltB64);
      });
    });
  });
}

// ── Run contract for MemoryKeyStorage ─────────────────────────────────────────

runKeyStorageContract('MemoryKeyStorage', () => new MemoryKeyStorage());

// ── Run contract for IndexedDBKeyStorage ──────────────────────────────────────
//
// Each test gets a fresh IDBFactory instance (fresh in-memory database) so
// tests are fully isolated — no leftover keys from previous tests.

runKeyStorageContract(
  'IndexedDBKeyStorage',
  () => new IndexedDBKeyStorage(new IDBFactory()),
);

// ── MemoryKeyStorage-specific ─────────────────────────────────────────────────

describe('MemoryKeyStorage.clear()', () => {
  it('removes all stored keys', async () => {
    const storage = new MemoryKeyStorage();
    await storage.generateAndStore('alice', '1234');
    await storage.generateAndStore('bob', '5678');
    storage.clear();
    expect(await storage.hasKey('alice')).toBe(false);
    expect(await storage.hasKey('bob')).toBe(false);
  });
});
