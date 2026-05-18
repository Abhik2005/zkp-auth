/**
 * @zkp-auth/server — in-memory challenge store with TTL + replay prevention
 *
 * This module provides `InMemoryChallengeStore`, the default `IChallengeStore`
 * implementation. Each stored entry carries its expiry timestamp so that a
 * single `consumeIfLive` call both validates freshness and atomically removes
 * the entry, making replay attacks impossible in a single-process deployment.
 *
 * Security properties:
 *
 * 1. **Expiry** — every challenge is stored with an absolute `expiresAt` wall-
 *    clock timestamp (milliseconds since epoch). `consumeIfLive` rejects entries
 *    whose `expiresAt` is in the past.
 *
 * 2. **Replay prevention** — `consumeIfLive` deletes the entry unconditionally
 *    before returning it. A second call for the same `sessionId` always returns
 *    `null`, even if the TTL has not yet elapsed.
 *
 * 3. **GC sweep** — a periodic interval clears expired-but-not-consumed entries
 *    so the Map does not grow without bound. The interval can be stopped with
 *    `destroy()`.
 *
 * Multi-process / Redis note: this store is correct only within a single
 * Node.js process. Horizontally scaled deployments must supply a Redis-backed
 * `IChallengeStore` via the `store` option on `zkpChallenge` / `zkpVerify`.
 */

import type { IChallengeStore } from './types.js';

// ---------------------------------------------------------------------------
// Internal entry type
// ---------------------------------------------------------------------------

interface ChallengeEntry {
  /** 32-byte challenge. */
  challenge: Uint8Array;
  /** Absolute expiry timestamp (Date.now() + ttlMs at insertion time). */
  expiresAt: number;
}

// ---------------------------------------------------------------------------
// InMemoryChallengeStore
// ---------------------------------------------------------------------------

/** Default sweep interval when none is specified: 30 seconds. */
const DEFAULT_SWEEP_INTERVAL_MS = 30_000;

/**
 * In-memory implementation of `IChallengeStore`.
 *
 * Thread-safe within a single Node.js event loop. Not safe across processes.
 *
 * @example
 * ```ts
 * const store = new InMemoryChallengeStore();
 * const options = { store, ttlMs: 60_000 };
 * app.post('/auth/challenge', zkpChallenge(options));
 * app.post('/auth/verify',   zkpVerify({ ...options, getPublicKey, jwtSecret }));
 * // On shutdown:
 * store.destroy();
 * ```
 */
export class InMemoryChallengeStore implements IChallengeStore {
  private readonly entries = new Map<string, ChallengeEntry>();
  private readonly sweepTimer: ReturnType<typeof setInterval>;

  /**
   * @param sweepIntervalMs How often to sweep expired entries. Default: 30 s.
   */
  constructor(sweepIntervalMs: number = DEFAULT_SWEEP_INTERVAL_MS) {
    this.sweepTimer = setInterval(() => this.sweep(), sweepIntervalMs);
    // Allow Node to exit even if the interval is still pending.
    if (typeof this.sweepTimer.unref === 'function') {
      this.sweepTimer.unref();
    }
  }

  /**
   * Store or replace the challenge for `sessionId`.
   *
   * Immediately evicts any pre-existing entry for the same session so that a
   * user who hits /challenge twice only gets the latest challenge.
   *
   * @param sessionId Arbitrary string key (typically the userId).
   * @param challenge 32-byte `Uint8Array`.
   * @param ttlMs     Time-to-live in milliseconds.
   */
  async set(sessionId: string, challenge: Uint8Array, ttlMs: number): Promise<void> {
    this.entries.set(sessionId, {
      challenge,
      expiresAt: Date.now() + ttlMs,
    });
  }

  /**
   * Atomically retrieve and delete the challenge for `sessionId` if it exists
   * and has not expired.
   *
   * Returns `null` when:
   * - No entry exists for `sessionId` (never stored, or already consumed).
   * - The entry has expired (`Date.now() >= expiresAt`).
   *
   * The deletion happens before returning, so any subsequent call — even one
   * that races within the same event-loop tick — will observe `null`.
   *
   * @param sessionId Arbitrary string key.
   * @returns         The 32-byte challenge or `null`.
   */
  async consumeIfLive(sessionId: string): Promise<Uint8Array | null> {
    const entry = this.entries.get(sessionId);

    // Delete unconditionally — even expired entries are removed here so that
    // the sweep does not also need to distinguish expired from consumed.
    if (entry !== undefined) {
      this.entries.delete(sessionId);
    }

    if (entry === undefined) {
      return null;
    }
    if (Date.now() >= entry.expiresAt) {
      return null;
    }
    return entry.challenge;
  }

  /**
   * Evict all expired entries from the map.
   *
   * Called automatically by the sweep interval. Safe to call manually (e.g.
   * in tests that advance fake timers).
   */
  sweep(): void {
    const now = Date.now();
    for (const [key, entry] of this.entries) {
      if (now >= entry.expiresAt) {
        this.entries.delete(key);
      }
    }
  }

  /**
   * Stop the internal sweep interval.
   *
   * Call this on application shutdown to allow the Node.js event loop to exit
   * cleanly. After calling `destroy()`, the store is no longer usable.
   */
  destroy(): void {
    clearInterval(this.sweepTimer);
  }

  /**
   * Return the current number of stored entries (including expired-but-not-
   * swept entries). Intended for testing and diagnostics only.
   */
  get size(): number {
    return this.entries.size;
  }
}
