// @zkp-auth/core — Property 15: Nonce buffer is zero-filled before `computeProof` returns
//
// Property 15: Nonce buffer is zero-filled before `computeProof` returns
// Validates: Requirements 6.4
// See design.md → "Components and Interfaces → compute-proof.ts" step 5
//     (the algorithm spec which mandates `r_bytes.fill(0)` after the
//     proof has been assembled), and
//     design.md → "Security Considerations → Memory hygiene" item 1
//     (the "best-effort zero-fill of nonce buffer" note), and
//     requirements.md → "Requirement 6.4" (the Core_Library SHALL
//     zero-fill the nonce buffer — best-effort — after `s` is computed
//     and before `computeProof` returns).
//
// For any valid input triple `(privateKey, password, challenge)`, after
// `computeProof` returns successfully, the 32-byte buffer that was
// returned by `randomBytes32()` and consumed by the implementation
// MUST have every byte equal to `0`.
//
// Why this is BEST-EFFORT — and what it does, and does NOT, prove:
//   This is a memory-hygiene contract, not a cryptographic guarantee.
//   JavaScript gives no hard guarantees about zeroization: a generational
//   GC may have relocated the buffer's backing memory before our wipe
//   ran, the JIT may have inlined a copy that lives in a register, and
//   the V8 heap can retain stale views that the language gives us no
//   handle to. This test only verifies that the implementation's
//   documented `r_bytes.fill(0)` call ran successfully on the EXACT
//   `Uint8Array` instance that the implementation received from
//   `randomBytes32()`. A heap snapshot or short-lived debugger session
//   that inspects THAT buffer will see zeros rather than the secret
//   nonce material; an attacker with deeper access (a hostile host,
//   raw memory scraping, V8 internals) is explicitly out of scope per
//   design "Security Considerations → Memory hygiene" and "Threat
//   model summary".
//
// Why we capture the EXACT buffer reference (and NOT a copy):
//   The property's whole subject is mutation in place. If the test
//   captured a copy of `randomBytes32()`'s return value, the
//   implementation's later `r_bytes.fill(0)` would zero the original
//   but leave the copy untouched, and the test would pass for the
//   wrong reason. By having the mock implementation return a fresh
//   `new Uint8Array(...)` AND store that same instance in the
//   module-scope `lastReturnedBuffer`, both the implementation's
//   `r_bytes` local and the test's `lastReturnedBuffer` are aliases
//   for the same backing buffer. When the implementation calls
//   `r_bytes.fill(0)`, the test sees the zeros through its alias.
//
// Why this works ONLY because the implementation operates on `r_bytes`
// in place:
//   The design (compute-proof.ts step 5) explicitly specifies that
//   `r_bytes` is the canonical buffer the implementation derives `r`
//   from, builds the commitment from, and then wipes — without an
//   intermediate defensive copy. If a future refactor were to copy
//   `r_bytes` into a fresh buffer before processing, the wipe would
//   land on the original (which the test sees) but the secret would
//   live on in the copy (which the test does NOT see), defeating the
//   memory-hygiene intent. Property 15 therefore also locks the
//   "no defensive copy of `r_bytes`" contract by the back door.
//
// Mocking pattern: same `vi.hoisted` + `vi.mock('../src/rng.js', ...)`
// scaffolding as `property-04-challenge-independence.test.ts` and
// `property-12-nonce-rng-only.test.ts`, with the small extension that
// the `mockImplementation` ALSO captures the returned buffer reference
// in a module-scope `lastReturnedBuffer` for the property body to
// inspect.
//
// Why the fixed RNG content is `numberToBytesLE(2n, 32)`:
//   Per design "Components and Interfaces → compute-proof.ts" step 4,
//   the implementation derives `r = reduceScalar(scalarFromBytesLE(r_bytes))`
//   and MUST redraw if `r === 0n` (Requirement 6.1 / 6.2). If our
//   fixed buffer happened to decode to a multiple of `L`, the
//   redraw loop would never terminate against this static mock.
//   Picking the encoding of the scalar `2` (which is definitively in
//   `[1, L)`) sidesteps the redraw entirely: the first draw is
//   accepted, exactly one buffer is produced, and that buffer is the
//   one we capture and assert is zero-filled. Same trick as
//   property-12.
//
// TDD red-phase note: `../src/compute-proof.js` does NOT exist yet —
// it is produced by task 7.6. Until then, this import will fail to
// resolve and the test will not run. That is the expected state for
// task 7.4. The package's `tsconfig.json` `"include": ["src/**/*"]`
// excludes `test/**/*` from typecheck scope, so `tsc --noEmit`
// remains clean even with this unresolved test-only import.
//
// Per-byte numeric equality on `Uint8Array` views is fine in test
// files: byte values are numbers in `[0, 255]`, not secret material,
// and the audit guard from task 13.1 scans `src/**/*.ts` only —
// `test/**/*.ts` is explicitly out of its scope.

import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import fc from 'fast-check';

// `vi.hoisted` lets the `vi.mock` factory below reference `rngMock`
// even though the factory is hoisted to the top of the module by
// Vitest. We use a non-generic `vi.fn()` and configure typing via
// `mockImplementation` to avoid the `Type '() => Uint8Array' does not
// satisfy the constraint 'any[]'` diagnostic that the single-generic
// `vi.fn<() => Uint8Array>()` form produces in this codebase's TS
// version (mirrors property-04 and property-12).
const rngMock = vi.hoisted(() => ({
  randomBytes32: vi.fn(),
}));

vi.mock('../src/rng.js', () => ({
  randomBytes32: rngMock.randomBytes32,
}));

// Imported AFTER `vi.mock` for reader clarity. Vitest's hoisting
// handles the actual ordering at runtime; the visual order here
// matches the human-reader's mental model of "set up the mock, then
// import the unit under test".
import { numberToBytesLE } from '@noble/curves/utils.js';

import { L } from '../src/encoding.js';
import { computeProof } from '../src/compute-proof.js';

// Module-scope capture slot for the buffer that the mocked
// `randomBytes32` most recently returned. Declared OUTSIDE
// `vi.hoisted` because the `vi.hoisted` machinery exists to make the
// mock factory's references resolve at hoist time — ordinary
// module-scope state used by the test body afterwards has no such
// constraint. `beforeEach` resets this to `null` so each property
// case starts fresh.
let lastReturnedBuffer: Uint8Array | null = null;

// The fixed 32-byte CSPRNG output every mocked `randomBytes32` call
// returns. We deliberately pick the little-endian encoding of the
// scalar `2` for the same reason property-12 does: `2 ∈ [1, L)`
// guarantees the implementation's redraw guard
// (`if (r === 0n) redraw`, design compute-proof.ts step 4) accepts
// the first draw, so the implementation calls `randomBytes32()`
// exactly once per `computeProof` invocation and the buffer we
// capture is unambiguously THE buffer the implementation used to
// construct the proof. Any value in `[1, L)` would prove the
// property equally well; the specific choice has no bearing on
// whether Property 15 holds.
const FIXED_RNG_CONTENT: Uint8Array = numberToBytesLE(2n, 32);

// TODO(11.1): replace each inline arbitrary below with the shared
// `arbValidPrivateKey`, `arbPassword`, and `arbChallenge32` from
// `./arbitraries.js` once task 11.1 lands. The bounds (`[1, L)` for
// scalars; `length ∈ [0, 4096]` for `password`; `length === 32` for
// `challenge`) are taken directly from Requirements 3.1, 3.5, 3.6,
// 3.7, and must match the shared arbitraries once those are
// introduced.
const arbValidPrivateKey: fc.Arbitrary<Uint8Array> = fc
  .bigInt({ min: 1n, max: L - 1n })
  .map((n) => numberToBytesLE(n, 32));

// TODO(11.1): replace with shared `arbChallenge32` from
// `./arbitraries.js` once task 11.1 lands.
const arbChallenge32: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 32,
  maxLength: 32,
});

// TODO(11.1): replace with shared `arbPassword` from
// `./arbitraries.js` once task 11.1 lands. Length bounds `[0, 4096]`
// match Requirement 3.7.
const arbPassword: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 0,
  maxLength: 4096,
});

describe('Property 15: Nonce buffer is zero-filled before computeProof returns', () => {
  beforeEach(() => {
    // Each property case gets a clean capture slot. Without this,
    // `lastReturnedBuffer` would carry over from the prior case
    // and a buggy implementation that simply never calls
    // `randomBytes32` could spuriously pass by inheriting the
    // previous case's already-zeroed buffer.
    lastReturnedBuffer = null;

    // Return a FRESH `Uint8Array` on every call AND capture that
    // exact instance in `lastReturnedBuffer`. The fresh allocation
    // matters for two reasons:
    //
    //   1. The implementation will mutate the buffer (it calls
    //      `r_bytes.fill(0)` per design compute-proof.ts step 5).
    //      Reusing a single static buffer across calls would mean
    //      the second call receives an already-zeroed buffer,
    //      which fails the redraw guard
    //      (`scalarFromBytesLE([0,...]) === 0n` — see Requirement
    //      6.1) and triggers an unbounded loop against this
    //      static mock.
    //   2. The test asserts the buffer's contents AFTER
    //      `computeProof` returns. If the test code held a
    //      reference to a buffer that was reused on a later call,
    //      observing it post-`computeProof` would be racing
    //      against the next mocked call, not against the wipe.
    //
    // `new Uint8Array(FIXED_RNG_CONTENT)` performs the byte copy
    // (the `Uint8Array` constructor copies from another typed
    // array). The returned buffer is then ASSIGNED to
    // `lastReturnedBuffer` and ALSO returned to the caller — both
    // bindings reference the SAME backing memory, which is the
    // whole point of this test (see file header on "the EXACT
    // buffer reference").
    rngMock.randomBytes32.mockImplementation((): Uint8Array => {
      const buf = new Uint8Array(FIXED_RNG_CONTENT);
      lastReturnedBuffer = buf;
      return buf;
    });
  });

  afterEach(() => {
    // Reset both implementation and call history so each `it` (and
    // any future appended block) starts with a fresh mock state.
    // Also clear the capture slot so a leaked reference cannot
    // affect a later test in the same suite.
    rngMock.randomBytes32.mockReset();
    lastReturnedBuffer = null;
  });

  it('every byte of the nonce buffer is zero after computeProof returns', () => {
    fc.assert(
      fc.property(
        arbValidPrivateKey,
        arbPassword,
        arbChallenge32,
        (privateKey, password, challenge) => {
          // Reset the capture slot at the start of each property
          // case as well. `beforeEach` sets it to `null` once per
          // `it` block, but `fc.assert` runs the body 100 times
          // INSIDE that single `it`, so the per-case reset has to
          // happen here. Without it, a previous case's already-
          // zeroed buffer could shadow a real failure in the
          // current case (e.g. an implementation that wipes on
          // call N but not on call N+1 would still appear to pass
          // case N+1 because we'd be looking at case N's buffer).
          lastReturnedBuffer = null;

          const proof = computeProof(privateKey, password, challenge);

          // Sanity: the proof itself must have the contracted
          // shape (64 bytes = `R || s`, Requirement 3.1). If
          // `computeProof` somehow returned a malformed value,
          // the zero-fill claim is moot — bail with `false` so
          // fast-check reports the failure clearly.
          if (!(proof instanceof Uint8Array) || proof.length !== 64) {
            return false;
          }

          // The mock MUST have fired at least once for this
          // property to be meaningful. If `lastReturnedBuffer`
          // is still `null`, the implementation never called
          // `randomBytes32()` — which itself violates Requirement
          // 6.1 (fresh CSPRNG nonce per `computeProof`) and the
          // dependency contract (`compute-proof.ts` is supposed
          // to import `randomBytes32` from `./rng.js`, which is
          // exactly the binding we mocked).
          if (lastReturnedBuffer === null) return false;

          // Sanity: `randomBytes32` is contracted to return 32
          // bytes (Requirement 1.5 / 2.4 / 3.10 — short reads
          // throw `RandomnessError` rather than reaching here),
          // and our mock honors that. If this length check ever
          // fires, the test's mock setup is wrong, not the
          // implementation.
          if (lastReturnedBuffer.length !== 32) return false;

          // The zero-fill claim itself (Requirement 6.4,
          // Property 15): every byte of the buffer the
          // implementation received from `randomBytes32()` MUST
          // be `0` after `computeProof` returns. We loop in JS
          // rather than calling `Buffer.equals(...)` or
          // `crypto.timingSafeEqual` because (a) timing safety
          // is irrelevant here — both `lastReturnedBuffer` and
          // the all-zero comparand are non-secret in this test
          // — and (b) a per-byte loop gives fast-check a clean
          // failure point if a single byte is non-zero, which
          // helps the shrinker localize an off-by-one in the
          // implementation's wipe.
          for (let i = 0; i < 32; i += 1) {
            if (lastReturnedBuffer[i] !== 0) return false;
          }

          return true;
        },
      ),
      { numRuns: 100 },
    );
  });
});
