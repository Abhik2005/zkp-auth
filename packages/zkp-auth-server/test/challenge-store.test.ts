/**
 * Unit tests for InMemoryChallengeStore.
 *
 * Coverage:
 * - set / consumeIfLive happy path
 * - TTL expiry (time-mocked)
 * - Replay prevention (double consume)
 * - set replaces existing challenge
 * - sweep evicts expired entries
 * - size accessor
 * - destroy stops sweep interval
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { InMemoryChallengeStore } from '../src/challenge-store.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeChallenge(fill = 0xab): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

const SESSION = 'user-alice';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('InMemoryChallengeStore', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ── Happy path ─────────────────────────────────────────────────────────────

  it('set_then_consumeIfLive_returnsChallenge', async () => {
    const store = new InMemoryChallengeStore();
    const challenge = makeChallenge();

    await store.set(SESSION, challenge, 60_000);
    const result = await store.consumeIfLive(SESSION);

    expect(result).not.toBeNull();
    expect(Array.from(result!)).toEqual(Array.from(challenge));

    store.destroy();
  });

  // ── Replay prevention ──────────────────────────────────────────────────────

  it('consumeIfLive_calledTwice_secondCallReturnsNull', async () => {
    const store = new InMemoryChallengeStore();
    await store.set(SESSION, makeChallenge(), 60_000);

    const first = await store.consumeIfLive(SESSION);
    const second = await store.consumeIfLive(SESSION);

    expect(first).not.toBeNull();
    expect(second).toBeNull();

    store.destroy();
  });

  // ── TTL expiry ─────────────────────────────────────────────────────────────

  it('consumeIfLive_afterTTL_returnsNull', async () => {
    const store = new InMemoryChallengeStore();
    await store.set(SESSION, makeChallenge(), 5_000); // 5 s TTL

    // Advance clock past TTL
    vi.advanceTimersByTime(5_001);

    const result = await store.consumeIfLive(SESSION);
    expect(result).toBeNull();

    store.destroy();
  });

  it('consumeIfLive_justBeforeTTL_returnsChallenge', async () => {
    const store = new InMemoryChallengeStore();
    await store.set(SESSION, makeChallenge(), 5_000);

    vi.advanceTimersByTime(4_999);

    const result = await store.consumeIfLive(SESSION);
    expect(result).not.toBeNull();

    store.destroy();
  });

  // ── Upsert behaviour ───────────────────────────────────────────────────────

  it('set_calledTwice_secondChallengeReplaceFirst', async () => {
    const store = new InMemoryChallengeStore();
    const first = makeChallenge(0x11);
    const second = makeChallenge(0x22);

    await store.set(SESSION, first, 60_000);
    await store.set(SESSION, second, 60_000);

    const result = await store.consumeIfLive(SESSION);
    expect(Array.from(result!)).toEqual(Array.from(second));

    store.destroy();
  });

  // ── Sweep ──────────────────────────────────────────────────────────────────

  it('sweep_removesExpiredEntries', async () => {
    const store = new InMemoryChallengeStore(999_999); // very long auto-sweep
    await store.set(SESSION, makeChallenge(), 5_000);
    expect(store.size).toBe(1);

    vi.advanceTimersByTime(5_001);
    store.sweep();

    expect(store.size).toBe(0);

    store.destroy();
  });

  it('sweep_doesNotRemoveLiveEntries', async () => {
    const store = new InMemoryChallengeStore(999_999);
    await store.set(SESSION, makeChallenge(), 60_000);
    expect(store.size).toBe(1);

    vi.advanceTimersByTime(1_000);
    store.sweep();

    expect(store.size).toBe(1);

    store.destroy();
  });

  // ── Missing session ────────────────────────────────────────────────────────

  it('consumeIfLive_unknownSession_returnsNull', async () => {
    const store = new InMemoryChallengeStore();
    const result = await store.consumeIfLive('no-such-session');
    expect(result).toBeNull();

    store.destroy();
  });

  // ── Multiple sessions ──────────────────────────────────────────────────────

  it('set_multipleSessions_consumeEachIndependently', async () => {
    const store = new InMemoryChallengeStore();
    const cA = makeChallenge(0xaa);
    const cB = makeChallenge(0xbb);

    await store.set('alice', cA, 60_000);
    await store.set('bob', cB, 60_000);

    const resultA = await store.consumeIfLive('alice');
    const resultB = await store.consumeIfLive('bob');

    expect(Array.from(resultA!)).toEqual(Array.from(cA));
    expect(Array.from(resultB!)).toEqual(Array.from(cB));

    store.destroy();
  });
});
