// @zkp-auth/core — Property 13: RNG anomaly produces RandomnessError
//
// Property 13: For any function `f ∈ { generateKeyPair, generateChallenge,
// computeProof }` and for any CSPRNG fault injected via
// `rng.randomBytes32` (the fault being either a thrown error, a return of
// fewer than 32 bytes, or — for `generateKeyPair` and `computeProof` —
// repeated draws that fail rejection sampling), invoking `f` with
// otherwise-valid arguments throws an instance of `RandomnessError` with
// `.code === 'RNG_FAILURE'`. No partial, zero-padded, or shape-valid
// output is returned.
//
// Validates: Requirements 1.5, 2.4, 3.10, 6.1
// See design.md → "Correctness Properties → Property 13" and
//     design.md → "Key design decisions → 2" (rejection-sampling bound) and
//     design.md → "Testing Strategy → Mocking strategy".
//
// Per tasks.md, this file is created here with ONLY the
// `describe('generateKeyPair', ...)` block (task 5.3). Tasks 6.4
// (`generateChallenge`) and 7.5 (`computeProof`) append additional
// `describe(...)` blocks to this same file later. Marker comments below
// indicate the insertion points for those appends.
//
// This test is fault-injection (Vitest `vi.mock`), not property-based via
// `fast-check`: the failure scenarios are enumerated, not generated. This
// matches the design's "Statistical tests" / "Mocking strategy" guidance
// — `fast-check` would burn CSPRNG output without adding signal to a
// closed enumeration of three failure modes.
//
// We use `vi.hoisted` to declare the mock RNG up front so the factory
// passed to `vi.mock` can reference it. `vi.mock` factories are hoisted
// above imports, so a normal module-scope variable would be undefined at
// factory-execution time; `vi.hoisted` is the canonical Vitest pattern
// for this.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { RandomnessError } from '../src/errors.js';
import { L, scalarToBytesLE } from '../src/encoding.js';

// `vi.hoisted` lets the `vi.mock` factory below reference `rngMock` even
// though the factory is hoisted to the top of the module by Vitest.
const rngMock = vi.hoisted(() => ({
  randomBytes32: vi.fn<() => Uint8Array>(),
}));

vi.mock('../src/rng.js', () => ({
  randomBytes32: rngMock.randomBytes32,
}));

// Imported AFTER `vi.mock` for reader clarity. Vitest's hoisting handles
// the actual ordering at runtime; the visual order here matches the
// human-reader's mental model of "set up the mock, then import the unit
// under test".
//
// NOTE (TDD red phase): `../src/keypair.js` does NOT exist yet — it is
// produced by task 5.4. Until then, this import will fail to resolve and
// the test file will not run. That is the expected state for task 5.3.
import { generateKeyPair } from '../src/keypair.js';
// NOTE (TDD red phase): `../src/challenge.js` does NOT exist yet — it is
// produced by task 6.5. Until then, this import will fail to resolve and
// the `generateChallenge` block below will not run. That is the expected
// state for task 6.4.
import { generateChallenge } from '../src/challenge.js';
// NOTE (TDD red phase): `../src/compute-proof.js` does NOT exist yet — it
// is produced by task 7.6. Until then, this import will fail to resolve
// and the `computeProof` block below will not run. That is the expected
// state for task 7.5.
import { computeProof } from '../src/compute-proof.js';

describe('Property 13 (generateKeyPair portion): RNG anomaly produces RandomnessError', () => {
  // `beforeEach` is intentionally imported but unused in this block; later
  // appended blocks (tasks 6.4, 7.5) may want it for per-test setup, and
  // keeping the import stable avoids a churned import line on those
  // appends.
  void beforeEach;

  afterEach(() => {
    // Reset both implementation and call history so each `it` starts
    // with a fresh mock state.
    rngMock.randomBytes32.mockReset();
  });

  it('throws RandomnessError when randomBytes32 throws', () => {
    rngMock.randomBytes32.mockImplementation(() => {
      throw new Error('simulated CSPRNG failure');
    });

    let caught: unknown;
    try {
      generateKeyPair();
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(RandomnessError);
    if (caught instanceof RandomnessError) {
      expect(caught.code).toBe('RNG_FAILURE');
    }
  });

  it('throws RandomnessError when randomBytes32 returns a short read (31 bytes)', () => {
    // The mock returns a 31-byte buffer directly, bypassing the
    // defensive length check in `rng.ts`'s wrapper (since we're mocking
    // AT that layer). This exercises the keypair generator's behavior
    // when its sole entropy source produces an unexpected shape.
    rngMock.randomBytes32.mockImplementation(() => new Uint8Array(31));

    let caught: unknown;
    try {
      generateKeyPair();
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(RandomnessError);
    if (caught instanceof RandomnessError) {
      expect(caught.code).toBe('RNG_FAILURE');
    }
  });

  it('throws RandomnessError when rejection sampling exhausts (every draw decodes to a scalar >= L)', () => {
    // Encode `L` itself as 32 little-endian bytes. The keypair
    // generator's acceptance check is `n >= 1n && n < L`; a candidate
    // that decodes to exactly `L` is rejected on the upper bound.
    // Returning this encoding on every call forces rejection-sampling
    // exhaustion at the `MAX_REJECTION_ITERATIONS = 256` bound from
    // design "Key design decisions → 2", which surfaces as a
    // `RandomnessError` with code `'RNG_FAILURE'`.
    const outOfRangeBytes = scalarToBytesLE(L);
    rngMock.randomBytes32.mockImplementation(() => {
      // Return a fresh copy on each call. The implementation may
      // mutate (e.g. zero-fill) the returned buffer, and we want
      // every iteration of the rejection loop to see a fresh
      // out-of-range encoding rather than a buffer some prior
      // iteration may have overwritten.
      return new Uint8Array(outOfRangeBytes);
    });

    let caught: unknown;
    try {
      generateKeyPair();
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(RandomnessError);
    if (caught instanceof RandomnessError) {
      expect(caught.code).toBe('RNG_FAILURE');
    }
    // Sanity: rejection sampling actually ran (i.e. the implementation
    // didn't accept the first out-of-range candidate). We don't assert
    // the exact bound (256) here because keypair.ts is free to choose
    // its own constant per design — we only assert "more than one draw"
    // to confirm the rejection loop is wired up.
    expect(rngMock.randomBytes32.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});

describe('Property 13 (generateChallenge portion): RNG anomaly produces RandomnessError', () => {
  // Note: `generateChallenge` does NOT perform rejection sampling — it
  // returns the CSPRNG output directly (see design "Components and
  // Interfaces → challenge.ts" and Property 13's enumeration of fault
  // modes: rejection-sampling exhaustion applies only to `generateKeyPair`
  // and `computeProof`). Hence this block has exactly two `it` cases:
  // throw and short-read.

  afterEach(() => {
    rngMock.randomBytes32.mockReset();
  });

  it('throws RandomnessError when randomBytes32 throws', () => {
    rngMock.randomBytes32.mockImplementation(() => {
      throw new Error('simulated CSPRNG failure');
    });

    // A small valid `sessionId` — its specific value is irrelevant to
    // Property 13. It just needs to pass `generateChallenge`'s shape
    // validation (1 ≤ length ≤ 256) so the test exercises the RNG path,
    // not the input-validation path.
    const sessionId = new Uint8Array([1, 2, 3]);

    let caught: unknown;
    try {
      generateChallenge(sessionId);
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(RandomnessError);
    if (caught instanceof RandomnessError) {
      expect(caught.code).toBe('RNG_FAILURE');
    }
  });

  it('throws RandomnessError when randomBytes32 returns a short read (31 bytes)', () => {
    // The mock returns a 31-byte buffer directly, bypassing the
    // defensive length check in `rng.ts`'s wrapper (since we're mocking
    // AT that layer). This exercises `generateChallenge`'s behavior
    // when its sole entropy source produces an unexpected shape.
    rngMock.randomBytes32.mockImplementation(() => new Uint8Array(31));

    const sessionId = new Uint8Array([1, 2, 3]);

    let caught: unknown;
    try {
      generateChallenge(sessionId);
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(RandomnessError);
    if (caught instanceof RandomnessError) {
      expect(caught.code).toBe('RNG_FAILURE');
    }
  });
});

describe('Property 13 (computeProof portion): RNG anomaly produces RandomnessError', () => {
  // This block exercises only the throw and short-read failure modes
  // per task 7.5's enumeration. The implementation also has a
  // `r === 0n` redraw loop (design.md → "Components and Interfaces →
  // compute-proof.ts" step 4), but that rejection-sampling exhaustion
  // path is NOT enumerated in Property 13's task-7.5 instructions and
  // is therefore not covered here.

  // The specific values below are arbitrary — they just need to pass
  // `computeProof`'s input validation (Requirements 3.5, 3.6, 3.7) so
  // each test exercises the RNG path, not the input-validation path.
  //
  // - `validPriv`: 32-byte little-endian encoding of scalar `2`, which
  //   sits firmly in `[1, L)` and so passes the private-key range check.
  // - `validPwd`: a short UTF-8 buffer (4 bytes), well within the
  //   `[0, 4096]` length bound on `password`.
  // - `validChal`: 32 bytes of `0x42`; only its shape matters here.
  const validPriv = ((): Uint8Array => {
    const k = new Uint8Array(32);
    k[0] = 0x02;
    return k;
  })();
  const validPwd = new TextEncoder().encode('test');
  const validChal = new Uint8Array(32).fill(0x42);

  afterEach(() => {
    rngMock.randomBytes32.mockReset();
  });

  it('throws RandomnessError when randomBytes32 throws', () => {
    rngMock.randomBytes32.mockImplementation(() => {
      throw new Error('simulated CSPRNG failure');
    });

    let caught: unknown;
    let returned: unknown;
    try {
      returned = computeProof(validPriv, validPwd, validChal);
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(RandomnessError);
    if (caught instanceof RandomnessError) {
      expect(caught.code).toBe('RNG_FAILURE');
    }
    // Per Requirement 3.10: no partial/zero-padded proof is emitted on
    // RNG failure. The function must throw rather than return.
    expect(returned).toBeUndefined();
  });

  it('throws RandomnessError when randomBytes32 returns a short read (31 bytes)', () => {
    // The mock returns a 31-byte buffer directly, bypassing the
    // defensive length check in `rng.ts`'s wrapper (since we're mocking
    // AT that layer). This exercises `computeProof`'s behavior when its
    // sole entropy source produces an unexpected shape.
    rngMock.randomBytes32.mockImplementation(() => new Uint8Array(31));

    let caught: unknown;
    let returned: unknown;
    try {
      returned = computeProof(validPriv, validPwd, validChal);
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(RandomnessError);
    if (caught instanceof RandomnessError) {
      expect(caught.code).toBe('RNG_FAILURE');
    }
    // Per Requirement 3.10: no partial/zero-padded proof is emitted on
    // RNG failure.
    expect(returned).toBeUndefined();
  });
});
