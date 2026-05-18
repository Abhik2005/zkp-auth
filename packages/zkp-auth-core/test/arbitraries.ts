// @zkp-auth/core — shared `fast-check` arbitraries for the property-test suite
//
// This module is the single source of every reusable `fast-check`
// arbitrary consumed by the property-based tests under
// `packages/zkp-auth-core/test/property-*.test.ts` and the
// example-based regression tests under
// `packages/zkp-auth-core/test/unit-*.test.ts`. Centralising the
// generators here serves three purposes:
//
//   1. **One contract per arbitrary.** Each public input's "valid
//      family" and "invalid family" is encoded exactly once. A test
//      regression in any one property file cannot drift the bound
//      independently of the others — every property exercises the
//      SAME bigint range for `arbValidPrivateKey`, the SAME length
//      window for `arbSessionId`, and so on.
//   2. **Shrinker quality across the suite.** `fast-check`'s shrinker
//      walks within the input space defined by an arbitrary. By
//      pinning each arbitrary to its specification's exact contract
//      (`fc.bigInt({ min: 1n, max: L - 1n })` for valid private keys,
//      `fc.uint8Array({ minLength: 32, maxLength: 32 })` for
//      challenges, etc.), every counterexample shrinks toward the
//      narrowest representative of its failure class — not toward an
//      arbitrary tolerance the test author chose ad hoc.
//   3. **Audit-surface tightness.** The "invalid family" generators
//      (`arbInvalidPrivateKeyShape`, `arbInvalidPassword`,
//      `arbInvalidChallenge`, `arbInvalidSessionId`,
//      `arbInvalidPublicKey`, `arbInvalidProofShape`,
//      `arbOutOfRangeSBytes`) are the inputs that drive the
//      typed-error contract in Property 8 (input validation) and
//      Property 9 (silent-`false` for attacker-chosen proof
//      material). Defining them in one file makes the audit reading
//      "every InvalidInputError-throwing input family is enumerated
//      here" a single-file check.
//
// Validates: contract surface for design.md → "Testing Strategy →
//            Custom arbitraries (generators)" (the 12 named arbitraries
//            in the bulleted list); consumed by tests that validate
//            Requirements 1.1–1.3, 2.1–2.5, 3.1–3.7, 3.10, 4.1–4.11,
//            5.3, 6.1–6.4, 7.1–7.5, 8.1–8.4, 9.1–9.5, 11.1–11.4, 11.6.
// See design.md → "Testing Strategy → Custom arbitraries (generators)"
//     for the canonical contract of each arbitrary; this file is the
//     implementation of that section.
// See design.md → "External API Surface §B–§C" for the noble-curves
//     symbols (`ed25519.Point.Fn.ORDER` aliased as `L`,
//     `numberToBytesLE`, `pointFromBytesSoft`) used to construct
//     valid encodings and to recognise invalid public-key bytes.
//
// SCOPE OF "INVALID" ARBITRARIES
//
// `arbInvalidPublicKey` returns ONLY `Uint8Array(32)` values that
// either fail Ed25519 point decoding via `pointFromBytesSoft` or
// encode the identity point. The non-Uint8Array and wrong-length
// failures for `publicKey` are NOT in this arbitrary's surface — they
// are exercised by Property 8's inline `arbInvalidPublicKeyShape`
// (test/property-08-input-validation.test.ts), which composes
// `arbWrongLengthUint8Array(32)` with `arbNotUint8Array`. Splitting
// the publicKey "invalid family" along this seam is intentional: the
// `arbInvalidPublicKey` arbitrary mirrors the THREE post-shape failure
// modes Requirement 4.5 distinguishes (decode failure, identity
// point), while shape failures (non-Uint8Array, wrong length) are a
// generic shape concern shared with every other Uint8Array-typed
// input.
//
// In contrast, `arbInvalidPrivateKeyShape` is a single union covering
// ALL FOUR private-key invalid sub-cases enumerated in design's
// "Custom arbitraries" section: non-Uint8Array, wrong-length
// Uint8Array, Uint8Array(32) decoding to 0, and Uint8Array(32)
// decoding to >= L. The name's "Shape" suffix reflects the design
// document's exact wording rather than narrowing the arbitrary's
// scope.
//
// PER-BYTE NUMERIC EQUALITY IS FINE IN THIS FILE
//
// This file is under `test/` and is NOT scanned by the audit guard
// (task 13.1, which scans `src/**/*.ts` only). Per-byte construction
// of `Uint8Array` views, `===`/`!==` comparisons against `null`, and
// equality on numeric loop counters are all permitted here — none of
// them touches secret material at runtime.
//
// CASTING NOTE FOR `Arbitrary<unknown>` ARBITRARIES
//
// The "invalid" arbitraries that include non-`Uint8Array` branches
// (`arbInvalidPrivateKeyShape`, `arbInvalidPassword`,
// `arbInvalidChallenge`, `arbInvalidSessionId`, `arbInvalidProofShape`)
// are typed as `fc.Arbitrary<unknown>` because they generate values
// that violate the static `Uint8Array` parameter type by design.
// Consumers cast at the call site
// (`computeProof(privateKey as Uint8Array, ...)`); the cast is a
// deliberate runtime-validation probe, not a type-correctness escape
// hatch. See test/property-08-input-validation.test.ts's
// "INPUT-CASTING NOTE" for the same convention applied to the
// inline arbitraries it currently defines.

import fc from 'fast-check';
import { ed25519 } from '@noble/curves/ed25519.js';
import { numberToBytesLE } from '@noble/curves/utils.js';

import { L, pointFromBytesSoft } from '../src/encoding.js';

// ---------------------------------------------------------------------
// Internal helpers (not exported)
// ---------------------------------------------------------------------

/**
 * `Uint8Array` arbitrary parameterised by a forbidden length, useful
 * for constructing "wrong-length" invalid families. The `filter`
 * excludes the exact required length so every produced value is
 * guaranteed to fail an `assertUint8ArrayLength(_, notLen, ...)`
 * check.
 *
 * Length range `[0, 128]` is wide enough to cover the realistic
 * mistake space (off-by-one shorter or longer than the required
 * length) without driving the shrinker toward extreme buffers that
 * carry no additional regression-detection value.
 */
function arbWrongLengthUint8Array(notLen: number): fc.Arbitrary<Uint8Array> {
  return fc
    .uint8Array({ minLength: 0, maxLength: 128 })
    .filter((b) => b.length !== notLen);
}

/**
 * Values that fail `instanceof Uint8Array`. The branches mirror the
 * realistic-mistake catalogue from
 * test/property-08-input-validation.test.ts:
 *
 *   - `null` and `undefined` — the JavaScript-style nullish cases;
 *   - `string` — strings have a `.length`, so a static `as Uint8Array`
 *     cast is the most plausible accidental-coercion path;
 *   - `number` — primitive value with no `.length`, exercises the
 *     `instanceof` short-circuit;
 *   - `array` of byte-valued integers — the most common mistake
 *     (passing `[1, 2, 3]` thinking JS will auto-coerce);
 *   - plain object `{}` — exercises the structural-shape rejection;
 *   - `Uint16Array` — has `.length` and `.byteLength` but is NOT a
 *     `Uint8Array` instance, so the `instanceof` check rejects it.
 *
 * Surface type is `unknown` because no single TypeScript type covers
 * every branch.
 */
const arbNotUint8Array: fc.Arbitrary<unknown> = fc.oneof(
  fc.constant(null),
  fc.constant(undefined),
  fc.string(),
  fc.integer(),
  fc.array(fc.integer({ min: 0, max: 255 })),
  fc.constant({}),
  fc.constant(new Uint16Array(32)),
);

// ---------------------------------------------------------------------
// Valid-input arbitraries
// ---------------------------------------------------------------------

/**
 * 32-byte little-endian encoding of a scalar `n ∈ [1, L)`, the
 * acceptance window `compute-proof.ts` enforces on its `privateKey`
 * input (Requirements 3.5, 11.4) and the range `keypair.ts` produces
 * via bounded rejection sampling (Requirement 1.2).
 *
 * Generation strategy is a `fc.oneof` between two branches:
 *
 *   1. An edge-case branch via `fc.constantFrom(...)` covering `1n`,
 *      `L - 1n`, and the small primes `2n, 3n, 5n, 7n, 11n, 13n,
 *      17n, 19n, 23n`. Per the task statement (and the design's
 *      "Custom arbitraries" bullet), biasing toward these values
 *      catches off-by-one regressions on the boundary scalars and
 *      makes shrinker counterexamples land on memorable values.
 *   2. A uniform-random branch via `fc.bigInt({ min: 1n, max: L - 1n })`
 *      that explores the bulk of the scalar field.
 *
 * Both branches are mapped through `numberToBytesLE(n, 32)` to
 * produce the canonical 32-byte little-endian encoding. We mix the
 * two branches with `fc.oneof` (uniform choice) rather than weighted
 * selection — the edge-case branch has 11 values vs. the random
 * branch's `L - 1 ≈ 2^252` values, so a single shrunk counterexample
 * almost always lands on the edge-case branch when the random
 * shrinker reaches a boundary.
 */
export const arbValidPrivateKey: fc.Arbitrary<Uint8Array> = fc
  .oneof(
    fc.constantFrom<bigint>(
      1n,
      2n,
      3n,
      5n,
      7n,
      11n,
      13n,
      17n,
      19n,
      23n,
      L - 1n,
    ),
    fc.bigInt({ min: 1n, max: L - 1n }),
  )
  .map((n) => numberToBytesLE(n, 32));

/**
 * `Uint8Array` of length `[0, 4096]` — the valid-shape window for
 * `password` per Requirement 3.7. Length `0` IS valid (`computeProof`
 * accepts an empty password) and is generated as the lower bound.
 *
 * Length cap of 4096 matches `compute-proof.ts`'s
 * `assertUint8ArrayLengthBetween(password, 0, 4096, ...)` upper
 * bound: any caller-supplied buffer of length up to and including
 * 4096 bytes is accepted by validation. The cap is wide enough to
 * admit any reasonable user-supplied password yet rejects payloads
 * large enough to suggest accidental data-passing or a DoS attempt.
 */
export const arbPassword: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 0,
  maxLength: 4096,
});

/**
 * 32-byte uniform-random `Uint8Array` — the valid-shape contract for
 * `challenge` on both the prover side (`computeProof`, Requirement
 * 3.6) and the verifier side (`verifyProof`, Requirement 4.6). Any
 * 32-byte buffer is structurally accepted; the verifier-chosen
 * randomness comes from `generateChallenge`'s CSPRNG draw, which
 * this arbitrary does NOT model — properties that need a "fresh
 * verifier challenge" can use the random output here as a stand-in
 * since `verifyProof` does not care how the bytes were chosen.
 */
export const arbChallenge32: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 32,
  maxLength: 32,
});

/**
 * `Uint8Array` of length `[1, 256]` — the valid-shape window for
 * `sessionId` per Requirement 2.2. The lower bound `1` rejects
 * empty inputs (which suggest a caller bug) and the upper bound
 * `256` rejects absurdly large inputs (which suggest accidental
 * payload-passing). Both bounds are inclusive, matching
 * `challenge.ts`'s
 * `assertUint8ArrayLengthBetween(sessionId, 1, 256, ...)` call.
 */
export const arbSessionId: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 1,
  maxLength: 256,
});

// ---------------------------------------------------------------------
// Invalid-input arbitraries (typed `Arbitrary<unknown>` where they
// admit non-Uint8Array values)
// ---------------------------------------------------------------------

/**
 * Invalid-family arbitrary for `privateKey` per design "Custom
 * arbitraries". Union of four sub-cases:
 *
 *   1. Non-`Uint8Array` (string, number, null, etc.).
 *   2. Wrong-length `Uint8Array` (length `≠ 32`).
 *   3. `Uint8Array(32)` decoding to scalar `0n` — exercised via the
 *      all-zero buffer constant. Requirement 11.4 mandates this case
 *      throw `INVALID_PRIVATE_KEY` because `x = 0` would make the
 *      proof trivially `R = r·G`, `s = r` and leak the nonce as the
 *      response.
 *   4. `Uint8Array(32)` decoding to scalar `>= L` — generated by
 *      sampling `bigInt({ min: L, max: 2^256 - 1 })` and re-encoding.
 *      Requirement 3.5 mandates this case throw `INVALID_PRIVATE_KEY`
 *      because keys outside `[1, L)` are integration errors against
 *      `generateKeyPair`'s in-range contract.
 *
 * Surface type is `unknown` because branch (1) admits non-Uint8Array
 * values. Consumers cast at the call site
 * (`computeProof(privateKey as Uint8Array, ...)`).
 */
export const arbInvalidPrivateKeyShape: fc.Arbitrary<unknown> = fc.oneof(
  arbNotUint8Array,
  arbWrongLengthUint8Array(32),
  // All-zero buffer: `scalarFromBytesLE(zero) === 0n`. Wrapped in
  // `fc.constant` so each iteration receives a fresh-but-
  // structurally-identical buffer; the test does not mutate it.
  fc.constant(new Uint8Array(32)),
  // Scalar `>= L` re-encoded as 32 little-endian bytes. The interval
  // `[L, 2^256)` is non-empty since `L < 2^253 < 2^256`.
  // `numberToBytesLE(n, 32)` accepts any `n < 2^256`, so the upper
  // bound `(1n << 256n) - 1n` keeps every generated value strictly
  // representable in 32 bytes.
  fc
    .bigInt({ min: L, max: (1n << 256n) - 1n })
    .map((n) => numberToBytesLE(n, 32)),
);

/**
 * Invalid-family arbitrary for `password` per Requirement 3.7. Two
 * sub-cases:
 *
 *   1. Non-`Uint8Array`.
 *   2. Oversize `Uint8Array` (length `> 4096`).
 *
 * Length `0` is intentionally NOT generated because it is VALID per
 * Requirement 3.7. The oversize upper bound (`4200`) is kept modest
 * above `4096` to bound shrinker work; any length strictly greater
 * than `4096` trips `assertUint8ArrayLengthBetween`'s upper-bound
 * check and produces the `INVALID_PASSWORD` error.
 */
export const arbInvalidPassword: fc.Arbitrary<unknown> = fc.oneof(
  arbNotUint8Array,
  fc.uint8Array({ minLength: 4097, maxLength: 4200 }),
);

/**
 * Invalid-family arbitrary for `challenge` per Requirements 3.6
 * (prover side) and 4.6 (verifier side). Two sub-cases:
 *
 *   1. Non-`Uint8Array`.
 *   2. Wrong-length `Uint8Array` (length `≠ 32`).
 *
 * The challenge must be exactly 32 bytes on both sides of the
 * protocol; this arbitrary surfaces every shape-failure case that
 * `assertUint8ArrayLength(challenge, 32, 'INVALID_CHALLENGE', ...)`
 * rejects.
 */
export const arbInvalidChallenge: fc.Arbitrary<unknown> = fc.oneof(
  arbNotUint8Array,
  arbWrongLengthUint8Array(32),
);

/**
 * Invalid-family arbitrary for `sessionId` per Requirement 2.2.
 * Three sub-cases:
 *
 *   1. Non-`Uint8Array`.
 *   2. Empty `Uint8Array` (length `0`).
 *   3. Oversize `Uint8Array` (length `> 256`).
 *
 * The valid window is `[1, 256]` inclusive, and
 * `challenge.ts`'s `assertUint8ArrayLengthBetween(sessionId, 1, 256,
 * ...)` rejects every value outside it. Empty buffers are split out
 * as `fc.constant(new Uint8Array(0))` rather than included in
 * `arbWrongLengthUint8Array` so the empty case has a deterministic
 * shrink target.
 */
export const arbInvalidSessionId: fc.Arbitrary<unknown> = fc.oneof(
  arbNotUint8Array,
  fc.constant(new Uint8Array(0)),
  // Oversize bound is `[257, 320]`; one byte over the 256-byte limit
  // is enough to trip the upper-bound check, and capping at 320
  // bounds shrinker work without sacrificing coverage.
  fc.uint8Array({ minLength: 257, maxLength: 320 }),
);

/**
 * Canonical 32-byte encoding of the Ed25519 identity point
 * `O = (x = 0, y = 1)` per RFC 8032 §5.1.2. Routed through
 * `ed25519.Point.ZERO.toBytes()` rather than hardcoded as a literal
 * `[0x01, 0x00, ...]` byte pattern: `ed25519` is the same module
 * `encoding.ts` imports and is the source of truth for Ed25519
 * encoding conventions, so any future change in `@noble/curves`'s
 * canonical encoding is picked up automatically here.
 */
const IDENTITY_PUBKEY_BYTES: Uint8Array = ed25519.Point.ZERO.toBytes();

/**
 * Invalid-family arbitrary for `publicKey` per Requirement 4.5,
 * specifically the POST-shape-validation failure modes (decode
 * failure, identity-point encoding). Returns ONLY `Uint8Array(32)`
 * values; non-Uint8Array and wrong-length cases are NOT in this
 * arbitrary's surface.
 *
 * Two sub-cases:
 *
 *   1. Random 32-byte arrays for which `pointFromBytesSoft(...)`
 *      returns `null` — i.e. bytes that fail Ed25519 point decoding
 *      (off-curve y-coordinate, non-canonical encoding, etc.). The
 *      filter acceptance rate is roughly 50% on random 32-byte
 *      inputs (the y-coordinate must satisfy the curve equation and
 *      admit a square root for `x`), comfortable for the
 *      `numRuns: 50` budget Property 8 uses.
 *   2. The constant identity-point encoding. Per Requirement 4.5,
 *      `verifyProof` MUST reject a `publicKey` decoding to the
 *      identity even though the encoding is structurally valid:
 *      with `publicKey = O`, the verification equation collapses
 *      to `s · G == R + c · O = R`, letting any forger satisfy
 *      it by picking any `s` and setting `R = s · G`.
 *
 * Surface type is `Uint8Array` rather than `unknown` because both
 * sub-cases produce well-formed 32-byte buffers; the failure mode
 * is on the decode side, not the shape side.
 */
export const arbInvalidPublicKey: fc.Arbitrary<Uint8Array> = fc.oneof(
  fc
    .uint8Array({ minLength: 32, maxLength: 32 })
    .filter((b) => pointFromBytesSoft(b) === null),
  fc.constant(IDENTITY_PUBKEY_BYTES),
);

/**
 * Invalid-family arbitrary for `proof` per Requirement 4.6 (proof
 * shape half). Two sub-cases:
 *
 *   1. Non-`Uint8Array`.
 *   2. Wrong-length `Uint8Array` (length `≠ 64`).
 *
 * THIS arbitrary is concerned exclusively with SHAPE failures that
 * trip `assertUint8ArrayLength(proof, 64, 'INVALID_PROOF', ...)`.
 * The "well-formed-but-mathematically-invalid proof" cases —
 * malformed `R` (cannot decode to Edwards point) and out-of-range
 * `s` (`s >= L`) — are covered separately by `arbOutOfRangeSBytes`
 * below and by inline filtering in
 * test/property-09-malformed-r-out-of-range-s.test.ts. Per
 * Requirements 4.7 and 4.8, those cases MUST surface as silent
 * `false` returns rather than typed-error throws, so they belong to
 * a different family from this arbitrary's "throws InvalidInputError
 * with code INVALID_PROOF" claim.
 */
export const arbInvalidProofShape: fc.Arbitrary<unknown> = fc.oneof(
  arbNotUint8Array,
  arbWrongLengthUint8Array(64),
);

// ---------------------------------------------------------------------
// Tampering arbitraries
// ---------------------------------------------------------------------

/**
 * `{ byteIndex, bitIndex }` pair specifying a single-bit tamper
 * position, used by Property 7 (tampering) and any future test that
 * walks a buffer flipping one bit at a time.
 *
 * Bounds:
 *
 *   - `byteIndex` in `[0, 63]` to cover the largest tamper target in
 *     the suite (`proof`, 64 bytes). For 32-byte targets
 *     (`publicKey`, `challenge`, `R_bytes`, `s_bytes`), the consumer
 *     narrows via `byteIndex % 32` — the same idiom Property 7
 *     already uses on its inline arbitrary
 *     (test/property-07-tampering.test.ts ~line 285 onward).
 *   - `bitIndex` in `[0, 7]` to cover all eight bit positions within
 *     the chosen byte.
 *
 * The two indices are returned as a structured record (rather than
 * two separate `fc.integer` arbitraries the consumer must thread
 * through their property body) so the shrinker can co-shrink a
 * counterexample to a minimal `(byteIndex, bitIndex)` pair without
 * the consumer having to manually pair them.
 */
export const arbBitFlipPosition: fc.Arbitrary<{
  byteIndex: number;
  bitIndex: number;
}> = fc.record({
  byteIndex: fc.integer({ min: 0, max: 63 }),
  bitIndex: fc.integer({ min: 0, max: 7 }),
});

/**
 * 32-byte little-endian encoding of a scalar `s ∈ [L, 2^256)`. Used
 * by Property 9 (test/property-09-malformed-r-out-of-range-s.test.ts)
 * to construct out-of-range `s_bytes` segments that
 * `verify-proof.ts` step 5 rejects with a silent `false` return per
 * Requirement 4.8.
 *
 * The interval is non-empty since `L < 2^253 < 2^256`.
 * `numberToBytesLE(n, 32)` accepts any `n < 2^256`, so the upper
 * bound `(1n << 256n) - 1n` keeps every generated value strictly
 * representable in 32 bytes — no `RangeError` from the encoder is
 * possible at this configured range.
 *
 * Distinct from `arbInvalidPrivateKeyShape`'s `>= L` sub-branch
 * because the consumer-side semantics differ: an out-of-range
 * `s_bytes` is attacker-chosen proof material that triggers a
 * silent `false` return (Requirement 4.8), while an out-of-range
 * `privateKey` decoding is a caller-supplied integration error that
 * triggers an `InvalidInputError` throw (Requirement 3.5). The two
 * arbitraries happen to share the same generation logic but are
 * exposed under separate names so each test reads at the
 * requirement level rather than the encoding level.
 */
export const arbOutOfRangeSBytes: fc.Arbitrary<Uint8Array> = fc
  .bigInt({ min: L, max: (1n << 256n) - 1n })
  .map((n) => numberToBytesLE(n, 32));
