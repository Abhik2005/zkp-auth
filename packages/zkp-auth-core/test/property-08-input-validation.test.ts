// @zkp-auth/core — Property 8: strict input validation throws
// `InvalidInputError` with stable `.code`
//
// Property 8: Strict input validation throws `InvalidInputError` with
//             stable `.code`
// Validates: Requirements 2.2, 3.5, 3.6, 3.7, 4.5, 4.6, 7.1, 7.2, 7.4, 11.4
// See design.md → "Correctness Properties → Property 8" and
//     design.md → "Components and Interfaces → validate.ts"
//                 (the single source of all shape/length error throws —
//                 every helper in `validate.ts` raises `InvalidInputError`
//                 with the caller-supplied stable code) and
//     design.md → "Components and Interfaces → errors.ts"
//                 (`InvalidInputError extends Error` with
//                 `readonly name = 'InvalidInputError'` and
//                 `readonly code: ErrorCode` — both fields are part of
//                 the public stable API surface, Requirement 7.1, 7.4) and
//     requirements.md → "Requirement 2.2" (sessionId shape: 1..256 byte
//                 Uint8Array → INVALID_SESSION_ID),
//                       "Requirement 3.5" (privateKey shape AND scalar
//                 range `[1, L)` → INVALID_PRIVATE_KEY; the `=== 0` and
//                 `>= L` checks are on the RAW decoding, not on
//                 `reduceScalar`'s output),
//                       "Requirement 3.6" (challenge shape:
//                 Uint8Array(32) → INVALID_CHALLENGE; same rule applies
//                 on the verify-proof side),
//                       "Requirement 3.7" (password shape: Uint8Array
//                 with `0 ≤ length ≤ 4096` → INVALID_PASSWORD; length 0
//                 IS valid),
//                       "Requirement 4.5" (publicKey shape, decoding,
//                 AND non-identity → INVALID_PUBLIC_KEY: the identity
//                 point `O = (0, 1)` is a VALID encoding but accepting
//                 it would let any forger satisfy the verification
//                 equation `s · G == R + c · O = R` by setting `R = s · G`
//                 for any chosen `s`),
//                       "Requirement 4.6" (challenge AND proof shape on
//                 the verify side: Uint8Array(32) for challenge,
//                 Uint8Array(64) for proof → INVALID_CHALLENGE,
//                 INVALID_PROOF respectively),
//                       "Requirement 7.1" (every public function throws
//                 a typed library error class — never raw `Error` —
//                 with the appropriate stable code),
//                       "Requirement 7.2" (RNG-failure paths surface
//                 `RandomnessError`; this property is concerned only
//                 with the InvalidInputError half),
//                       "Requirement 7.4" (the `.code` field is the
//                 stable identifier callers MUST pattern-match on
//                 instead of parsing `.message`; this property locks
//                 BOTH halves: the typed-error class AND the stable
//                 `.code` field), and
//                       "Requirement 11.4" (privateKey value of `0` —
//                 i.e. raw decoding to scalar `0n` — MUST throw
//                 INVALID_PRIVATE_KEY: `x = 0` would make the proof
//                 trivially `R = r·G`, `s = r` and leak the nonce as
//                 the response).
//
// THE PROPERTY 8 CLAIM
//
// For every entry-point public function (`generateChallenge`,
// `computeProof`, `verifyProof`) and for every "invalid family" of
// input documented in the source files' validation steps, calling the
// function with that input MUST throw an error that satisfies all
// THREE of:
//
//   1. `e instanceof InvalidInputError`        (the class identity)
//   2. `e.name === 'InvalidInputError'`        (the readonly name field)
//   3. `e.code === '<expected stable code>'`   (the readonly code field)
//
// All three are required because they are independently observable in
// real consumer code:
//
//   • Some callers use `e instanceof InvalidInputError` (typed
//     pattern-matching when the class is in scope).
//   • Some callers use `e.name === 'InvalidInputError'` (the duck-typed
//     alternative when an identical-shape class arrives across a
//     bundling boundary that breaks `instanceof`, e.g. multiple copies
//     of the package).
//   • Every caller is expected to use `.code` for the actual remediation
//     branch (Requirement 7.4 explicitly tells callers NOT to parse
//     `.message`).
//
// A regression that produced an error satisfying only one or two of
// the three would silently break some consumers and go unnoticed; the
// three-way assertion catches all such regressions in a single test.
//
// THE SIX FAMILIES — CALL-SITE PROVENANCE
//
// Each describe block below mirrors one of the six entry-point ×
// parameter combinations enumerated in the task statement. The error
// code each family must produce is fixed at a SPECIFIC line in the
// source file:
//
//   1. `generateChallenge(sessionId)` invalid family
//      → `INVALID_SESSION_ID`. Validation source:
//      `assertUint8ArrayLengthBetween(sessionId, 1, 256,
//      'INVALID_SESSION_ID', 'sessionId')` in `src/challenge.ts`.
//      Invalid family = non-`Uint8Array`, length `0`, or length `> 256`.
//
//   2. `computeProof` invalid `privateKey`
//      → `INVALID_PRIVATE_KEY`. Validation source:
//      `assertUint8ArrayLength(privateKey, 32, 'INVALID_PRIVATE_KEY',
//      'privateKey')` in `src/compute-proof.ts` (shape/length), AND a
//      subsequent explicit `if (n_raw === 0n || n_raw >= L) throw new
//      InvalidInputError('INVALID_PRIVATE_KEY', ...)` (scalar range,
//      Requirements 3.5 and 11.4). Invalid family splits into three
//      sub-cases: wrong shape/length, raw decoding to `0`, raw
//      decoding `≥ L`.
//
//   3. `computeProof` AND `verifyProof` invalid `challenge`
//      → `INVALID_CHALLENGE`. Validation source:
//      `assertUint8ArrayLength(challenge, 32, 'INVALID_CHALLENGE',
//      'challenge')` in BOTH `src/compute-proof.ts` and
//      `src/verify-proof.ts`. Invalid family = non-`Uint8Array` or
//      length `≠ 32`. We exercise both call sites in the same describe
//      block to lock that the `INVALID_CHALLENGE` code is consistent
//      across the prover and verifier API surface.
//
//   4. `computeProof` invalid `password`
//      → `INVALID_PASSWORD`. Validation source:
//      `assertUint8Array(password, 'INVALID_PASSWORD', 'password')`
//      followed by `assertUint8ArrayLengthBetween(password, 0, 4096,
//      'INVALID_PASSWORD', 'password')` in `src/compute-proof.ts`.
//      Invalid family = non-`Uint8Array` or length `> 4096`. Note:
//      length `0` IS valid per Requirement 3.7, so we explicitly do
//      NOT generate length-zero counterexamples.
//
//   5. `verifyProof` invalid `publicKey`
//      → `INVALID_PUBLIC_KEY`. Validation source: in
//      `src/verify-proof.ts`,
//      `assertUint8ArrayLength(publicKey, 32, 'INVALID_PUBLIC_KEY',
//      'publicKey')` (shape/length), then a strict decode via
//      `pointFromBytesStrict` whose `CryptoError` is re-wrapped into
//      `InvalidInputError('INVALID_PUBLIC_KEY', ...)`, then a
//      `PK.is0()` check that throws
//      `InvalidInputError('INVALID_PUBLIC_KEY', 'publicKey decodes to
//      the identity point')` (Requirement 4.5). Invalid family splits
//      into three sub-cases: wrong shape/length, non-decodable bytes,
//      identity-point encoding.
//
//   6. `verifyProof` invalid `proof` shape
//      → `INVALID_PROOF`. Validation source:
//      `assertUint8ArrayLength(proof, 64, 'INVALID_PROOF', 'proof')`
//      in `src/verify-proof.ts`. Invalid family = non-`Uint8Array` or
//      length `≠ 64`. THIS family is concerned only with SHAPE — the
//      "well-formed-but-mathematically-invalid proof" case (e.g.
//      malformed `R`, out-of-range `s`) is locked separately by
//      Property 9, which asserts those cases return `false` rather
//      than throw.
//
// PROPERTY 8 vs. PROPERTIES 6, 7, 9 — RESPONSIBILITY SPLIT
//
//   • Property 6 (round-trip) and Property 7 (single-bit tampering)
//     operate on inputs that are already well-formed enough to reach
//     the verification equation. They make claims about return values
//     (`true` for honest tuples, `false` for tampered ones), not about
//     thrown errors.
//
//   • Property 8 (THIS file) operates on inputs that are SHAPE- or
//     RANGE-invalid — i.e. they fail validation before reaching any
//     curve math or hash computation. The claim is exclusively about
//     the thrown `InvalidInputError`'s identity, name, and code.
//
//   • Property 9 operates on inputs that are SHAPE-valid but contain
//     attacker-chosen proof material (malformed `R`, out-of-range `s`).
//     Per Requirement 4.7 / 4.8, those cases MUST NOT throw — they
//     must silently return `false` to deny an oracle. Property 9
//     asserts the silent-`false`; Property 8 asserts the throw on the
//     SHAPE-invalid case.
//
//   The three properties together exhaustively cover the verify path's
//   error model: throw on caller-side shape/decode/identity faults,
//   silent `false` on attacker-controlled proof material faults, and
//   `true`/`false` on well-formed proofs based on the equation.
//
// INPUT-CASTING NOTE
//
// fast-check's `arbNotUint8Array` arbitrary intentionally produces
// values that fail `instanceof Uint8Array` — `null`, `undefined`,
// strings, numbers, plain objects, regular arrays, even other typed
// arrays like `Uint16Array`. Each entry-point function's TypeScript
// signature declares its parameters as `Uint8Array`, so passing these
// values violates the static type. We cast to `Uint8Array` at the
// call site — `generateChallenge(badValue as unknown as Uint8Array)` —
// because the WHOLE POINT of Property 8 is to assert the runtime
// validation rejects what the static types would permit. The cast is
// a deliberate contract violation, not a type-correctness escape
// hatch.
//
// IDENTITY-POINT ENCODING
//
// The Ed25519 identity point `O = (x = 0, y = 1)` is encoded per RFC
// 8032 §5.1.2 as the 32-byte little-endian encoding of `y = 1`, with
// the sign bit of `x = 0` packed into the high bit of the last byte.
// `y = 1` little-endian over 32 bytes is `[0x01, 0x00, ..., 0x00]`,
// and the sign bit of `x = 0` is `0`, so the identity encoding is
// exactly `Uint8Array([1, 0, 0, ..., 0])` (length 32). Rather than
// hardcode this and risk drift if `@noble/curves` ever changes its
// canonical encoding, we route through `ed25519.Point.ZERO.toBytes()`
// directly — `ed25519` is the same module `encoding.ts` imports and
// is the source of truth for Ed25519 encoding conventions across the
// codebase.
//
// VALIDATION-ORDER ASSUMPTIONS
//
// `verifyProof`'s validation order (`src/verify-proof.ts` step 1) is:
// `publicKey` → `challenge` → `proof`. To exercise the
// `INVALID_CHALLENGE` branch on the verify side in isolation, we pass
// a well-formed `publicKey` (a `Uint8Array(32)` decoding to a
// non-identity point) and a well-formed `proof` (an honest 64-byte
// proof from `__forTesting__.computeProofWithFixedNonce`) alongside an
// INVALID `challenge`. Likewise, to exercise `INVALID_PROOF` we pass
// well-formed `publicKey` and `challenge` alongside an invalid
// `proof`. `INVALID_PUBLIC_KEY` exercises the FIRST validation step,
// so it does not need well-formed `challenge`/`proof` to surface — but
// we pass well-formed ones anyway to keep every test case cleanly
// targeting a single invalid input.
//
// Per-byte construction of `Uint8Array` views is fine in test files:
// byte values are numbers in `[0, 255]`, not secret material, and the
// audit guard from task 13.1 scans `src/**/*.ts` only — `test/**/*.ts`
// is explicitly out of its scope.
//
// TODO(11.1): replace each inline arbitrary below with the shared
// arbitraries from `./arbitraries.js` once task 11.1 lands. The
// invalid families this property exercises are precisely the
// `arbInvalidPrivateKeyShape`, `arbInvalidPassword`,
// `arbInvalidChallenge`, `arbInvalidSessionId`, `arbInvalidPublicKey`,
// and `arbInvalidProofShape` arbitraries listed in design "Testing
// Strategy → Custom arbitraries", and once those are introduced this
// file should import from `./arbitraries.js` rather than define its
// own.

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';

import { numberToBytesLE } from '@noble/curves/utils.js';
import { ed25519 } from '@noble/curves/ed25519.js';

import { generateChallenge } from '../src/challenge.js';
import { computeProof, __forTesting__ as cpForTesting } from '../src/compute-proof.js';
import { verifyProof } from '../src/verify-proof.js';
import {
  L,
  BASE,
  scalarFromBytesLE,
  pointToBytes,
} from '../src/encoding.js';
import { InvalidInputError } from '../src/errors.js';

// --- Inline arbitraries (TODO 11.1) ---------------------------------

// 32-byte little-endian encoding of a scalar `n ∈ [1, L)`. Used to
// construct VALID privateKey buffers in cases where we want to make
// ONE other input invalid at a time.
const arbValidPrivateKey32: fc.Arbitrary<Uint8Array> = fc
  .bigInt({ min: 1n, max: L - 1n })
  .map((n) => numberToBytesLE(n, 32));

// 32-byte challenge — uniform random bytes. Valid by Requirement 3.6
// / 4.6 since any 32-byte buffer is an acceptable challenge shape.
const arbValidChallenge32: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 32,
  maxLength: 32,
});

// Valid password: any `Uint8Array` with `0 ≤ length ≤ 4096`. We use a
// modest length bound here since these are only used as the "valid
// other input" in cases where some OTHER input is the invalid one.
const arbValidPassword: fc.Arbitrary<Uint8Array> = fc.uint8Array({
  minLength: 0,
  maxLength: 64,
});

// Values that fail `instanceof Uint8Array`. Includes the four
// JavaScript-style nullish/primitive cases (null, undefined, strings,
// numbers), a different typed array (`Uint16Array` — has `.length`
// and `.byteLength` but is NOT a `Uint8Array` instance), a plain
// object, and a regular array of byte-valued integers (the most
// common mistake — callers who pass `[1, 2, 3]` thinking JavaScript
// will auto-coerce). The arbitrary itself is `Arbitrary<unknown>`
// since fast-check has no single type covering all of these; we cast
// at the call site (see "INPUT-CASTING NOTE" in the file header).
const arbNotUint8Array: fc.Arbitrary<unknown> = fc.oneof(
  fc.constant(null),
  fc.constant(undefined),
  fc.string(),
  fc.integer(),
  fc.array(fc.integer({ min: 0, max: 255 })),
  fc.constant({}),
  fc.constant(new Uint16Array(32)),
);

// Wrong-length `Uint8Array`s — produced for cases where 32 or 64 is
// the required length. The filter excludes the exact required length
// so the arbitrary always produces a length-mismatch counterexample.
function arbWrongLengthUint8Array(notLen: number): fc.Arbitrary<Uint8Array> {
  return fc
    .uint8Array({ minLength: 0, maxLength: 128 })
    .filter((b) => b.length !== notLen);
}

// All-zero 32-byte buffer: `scalarFromBytesLE(arbZeroPrivateKey)` is
// `0n`, which `compute-proof.ts` rejects via the explicit
// `if (n_raw === 0n || n_raw >= L)` check (Requirement 11.4).
const arbZeroPrivateKey: fc.Arbitrary<Uint8Array> = fc.constant(new Uint8Array(32));

// Oversize private key: any scalar in `[L, 2^256)` re-encoded as 32
// little-endian bytes. The interval is non-empty since `L < 2^253 <
// 2^256`. `numberToBytesLE(n, 32)` accepts any `n < 2^256`, so the
// `max: (1n << 256n) - 1n` upper bound keeps every generated value
// strictly representable in 32 bytes.
const arbOversizePrivateKey: fc.Arbitrary<Uint8Array> = fc
  .bigInt({ min: L, max: (1n << 256n) - 1n })
  .map((n) => numberToBytesLE(n, 32));

// Invalid sessionId family per Requirement 2.2. Three sub-cases:
// empty (length 0), oversize (length > 256), or non-Uint8Array. The
// arbitrary surface type is `unknown` because of the not-Uint8Array
// branch.
const arbInvalidSessionIdShape: fc.Arbitrary<unknown> = fc.oneof(
  fc.constant(new Uint8Array(0)),
  fc.uint8Array({ minLength: 257, maxLength: 320 }),
  arbNotUint8Array,
);

// Invalid password family per Requirement 3.7. Two sub-cases:
// oversize (length > 4096) or non-Uint8Array. Length 0 is
// intentionally NOT generated because it is VALID. The oversize
// upper bound is kept modest above 4096 to bound shrinker work; any
// length strictly greater than 4096 trips the bound check.
const arbInvalidPasswordShape: fc.Arbitrary<unknown> = fc.oneof(
  fc.uint8Array({ minLength: 4097, maxLength: 4200 }),
  arbNotUint8Array,
);

// Invalid challenge family per Requirements 3.6 and 4.6. The
// challenge must be exactly 32 bytes; this family covers
// non-Uint8Array AND wrong-length Uint8Array cases.
const arbInvalidChallengeShape: fc.Arbitrary<unknown> = fc.oneof(
  arbWrongLengthUint8Array(32),
  arbNotUint8Array,
);

// Invalid proof shape family per Requirement 4.6 (proof half). The
// proof must be exactly 64 bytes; this family covers non-Uint8Array
// AND wrong-length Uint8Array cases.
const arbInvalidProofShape: fc.Arbitrary<unknown> = fc.oneof(
  arbWrongLengthUint8Array(64),
  arbNotUint8Array,
);

// Invalid privateKey shape (excluding the in-shape range failures
// `=== 0` and `>= L`, which have their own dedicated arbitraries).
// Covers non-Uint8Array and wrong-length cases per Requirement 3.5.
const arbInvalidPrivateKeyShape: fc.Arbitrary<unknown> = fc.oneof(
  arbWrongLengthUint8Array(32),
  arbNotUint8Array,
);

// Random 32-byte arrays that fail Ed25519 point decoding. The filter
// keeps only those bytes for which decoding throws — i.e. the bytes
// `pointFromBytesStrict` would reject and `pointFromBytesSoft` would
// return `null` for. Acceptance rate is roughly 50% on random 32-byte
// inputs (the y-coordinate must satisfy the curve equation and admit
// a square root for `x`), comfortable for the per-family `numRuns`
// budget. We use the `ed25519.Point.fromBytes` path directly here
// (rather than importing `pointFromBytesSoft`) since this arbitrary
// is the test-side analogue to `arbInvalidPublicKey` from task 11.1's
// design and the call surface here is small.
const arbNonDecodablePublicKey: fc.Arbitrary<Uint8Array> = fc
  .uint8Array({ minLength: 32, maxLength: 32 })
  .filter((b) => {
    try {
      ed25519.Point.fromBytes(b);
      return false;
    } catch {
      return true;
    }
  });

// The Ed25519 identity-point encoding `O = (x = 0, y = 1)`. Routing
// through `ed25519.Point.ZERO.toBytes()` keeps this arbitrary
// resilient to any future change in `@noble/curves`'s canonical
// encoding — no hardcoded `[0x01, 0x00, ..., 0x00]` byte pattern to
// drift on us.
const IDENTITY_PUBKEY: Uint8Array = ed25519.Point.ZERO.toBytes();
const arbIdentityPublicKey: fc.Arbitrary<Uint8Array> = fc.constant(IDENTITY_PUBKEY);

// Invalid publicKey "shape" family (non-Uint8Array OR wrong length).
// The other two invalid publicKey sub-cases (non-decodable and
// identity) live in their own describe-block sections so each
// sub-case can use the most appropriate arbitrary type.
const arbInvalidPublicKeyShape: fc.Arbitrary<unknown> = fc.oneof(
  arbWrongLengthUint8Array(32),
  arbNotUint8Array,
);

// --- Test helpers ----------------------------------------------------

/**
 * Asserts the three independent halves of Property 8's claim on a
 * thrown error: it is an `InvalidInputError` instance, its `.name`
 * field equals `'InvalidInputError'`, and its `.code` field equals
 * `expectedCode`. All three are required because each one is
 * independently observable in real consumer code (see file header).
 */
function expectInvalidInputError(e: unknown, expectedCode: string): void {
  expect(e).toBeInstanceOf(InvalidInputError);
  expect((e as InvalidInputError).name).toBe('InvalidInputError');
  expect((e as InvalidInputError).code).toBe(expectedCode);
}

/**
 * Builds an honest 64-byte proof for a given valid `(privateKey,
 * password, challenge)` triple via the test-only fixed-nonce hook.
 * Used when a property body needs a well-formed `proof` to pair
 * with an invalid `publicKey` or `challenge` so the verify path's
 * failure mode is isolated to the input under test.
 *
 * The fixed-nonce hook makes a defensive copy of `r_bytes`
 * internally, so the caller's `r_bytes` constant is safe to re-use
 * across many invocations.
 */
function buildHonestProof(
  privateKey: Uint8Array,
  password: Uint8Array,
  challenge: Uint8Array,
): Uint8Array {
  // A fixed nonce in `[1, L)` — encoded as `numberToBytesLE(1n, 32)`.
  // Any value in range works; `1n` is the smallest non-zero choice.
  const r_bytes = numberToBytesLE(1n, 32);
  return cpForTesting.computeProofWithFixedNonce(privateKey, password, challenge, r_bytes);
}

/**
 * Derives the publicKey for a given valid privateKey using the SAME
 * scalar derivation `compute-proof.ts` uses internally
 * (`x = scalarFromBytesLE(privateKey)`; `publicKey =
 * pointToBytes(BASE.multiply(x))`). Used to obtain a well-formed
 * non-identity publicKey for the `verifyProof` test cases that
 * vary OTHER inputs.
 */
function derivePublicKey(privateKey: Uint8Array): Uint8Array {
  const x = scalarFromBytesLE(privateKey);
  return pointToBytes(BASE.multiply(x));
}

// --- Property 8 -----------------------------------------------------

describe('Property 8 — strict input validation throws InvalidInputError with stable .code', () => {
  // -----------------------------------------------------------------
  // Family 1: generateChallenge invalid sessionId → INVALID_SESSION_ID
  // -----------------------------------------------------------------
  describe('1. generateChallenge invalid sessionId → INVALID_SESSION_ID', () => {
    // Validation source: `assertUint8ArrayLengthBetween(sessionId, 1,
    // 256, 'INVALID_SESSION_ID', 'sessionId')` in src/challenge.ts.
    // Invalid family covers non-Uint8Array, length 0, and length > 256.
    it('throws InvalidInputError with code INVALID_SESSION_ID', () => {
      fc.assert(
        fc.property(arbInvalidSessionIdShape, (sessionId) => {
          try {
            generateChallenge(sessionId as Uint8Array);
            throw new Error('Expected throw, got success');
          } catch (e) {
            expectInvalidInputError(e, 'INVALID_SESSION_ID');
          }
        }),
        { numRuns: 50 },
      );
    });
  });

  // -----------------------------------------------------------------
  // Family 2: computeProof invalid privateKey → INVALID_PRIVATE_KEY
  // -----------------------------------------------------------------
  // Three sub-cases per Requirements 3.5 and 11.4:
  //   2a. wrong shape/length (non-Uint8Array or Uint8Array of length ≠ 32)
  //   2b. raw decoding to scalar `0n` (Requirement 11.4)
  //   2c. raw decoding to scalar `≥ L` (Requirement 3.5)
  describe('2. computeProof invalid privateKey → INVALID_PRIVATE_KEY', () => {
    it('throws on wrong shape or wrong length (non-Uint8Array(32))', () => {
      fc.assert(
        fc.property(
          arbInvalidPrivateKeyShape,
          arbValidPassword,
          arbValidChallenge32,
          (privateKey, password, challenge) => {
            try {
              computeProof(privateKey as Uint8Array, password, challenge);
              throw new Error('Expected throw, got success');
            } catch (e) {
              expectInvalidInputError(e, 'INVALID_PRIVATE_KEY');
            }
          },
        ),
        { numRuns: 50 },
      );
    });

    it('throws when privateKey decodes to scalar 0', () => {
      // Requirement 11.4: `x = 0` would make the proof trivially
      // `R = r·G`, `s = r` and leak the nonce as the response. The
      // explicit `if (n_raw === 0n || n_raw >= L)` branch in
      // compute-proof.ts catches this before any curve math runs.
      fc.assert(
        fc.property(
          arbZeroPrivateKey,
          arbValidPassword,
          arbValidChallenge32,
          (privateKey, password, challenge) => {
            try {
              computeProof(privateKey, password, challenge);
              throw new Error('Expected throw, got success');
            } catch (e) {
              expectInvalidInputError(e, 'INVALID_PRIVATE_KEY');
            }
          },
        ),
        { numRuns: 50 },
      );
    });

    it('throws when privateKey decodes to scalar >= L', () => {
      // Requirement 3.5: any value outside `[1, L)` is an
      // integration error against `generateKeyPair`'s contract that
      // all produced keys are in-range. We surface it verbatim
      // rather than silently reduce.
      fc.assert(
        fc.property(
          arbOversizePrivateKey,
          arbValidPassword,
          arbValidChallenge32,
          (privateKey, password, challenge) => {
            try {
              computeProof(privateKey, password, challenge);
              throw new Error('Expected throw, got success');
            } catch (e) {
              expectInvalidInputError(e, 'INVALID_PRIVATE_KEY');
            }
          },
        ),
        { numRuns: 50 },
      );
    });
  });

  // -----------------------------------------------------------------
  // Family 3: computeProof AND verifyProof invalid challenge
  //          → INVALID_CHALLENGE
  // -----------------------------------------------------------------
  // Validation source: `assertUint8ArrayLength(challenge, 32,
  // 'INVALID_CHALLENGE', 'challenge')` in BOTH src/compute-proof.ts
  // AND src/verify-proof.ts. We exercise both call sites to lock
  // that the `INVALID_CHALLENGE` code is consistent across the
  // prover AND verifier API surface. For the verifyProof case,
  // `publicKey` and `proof` are well-formed by construction so
  // `INVALID_CHALLENGE` is the only failure mode reachable.
  describe('3. computeProof and verifyProof invalid challenge → INVALID_CHALLENGE', () => {
    it('computeProof throws on invalid challenge', () => {
      fc.assert(
        fc.property(
          arbValidPrivateKey32,
          arbValidPassword,
          arbInvalidChallengeShape,
          (privateKey, password, challenge) => {
            try {
              computeProof(privateKey, password, challenge as Uint8Array);
              throw new Error('Expected throw, got success');
            } catch (e) {
              expectInvalidInputError(e, 'INVALID_CHALLENGE');
            }
          },
        ),
        { numRuns: 50 },
      );
    });

    it('verifyProof throws on invalid challenge', () => {
      fc.assert(
        fc.property(
          arbValidPrivateKey32,
          arbValidPassword,
          arbValidChallenge32,
          arbInvalidChallengeShape,
          (privateKey, password, validChallenge, invalidChallenge) => {
            // Build a well-formed publicKey AND a well-formed honest
            // proof under a DIFFERENT (valid) challenge. The verify
            // call uses the INVALID challenge — so the only failure
            // mode reachable is the `INVALID_CHALLENGE` shape check
            // (verify-proof.ts step 1, second assertion).
            const publicKey = derivePublicKey(privateKey);
            const proof = buildHonestProof(privateKey, password, validChallenge);
            try {
              verifyProof(publicKey, invalidChallenge as Uint8Array, proof);
              throw new Error('Expected throw, got success');
            } catch (e) {
              expectInvalidInputError(e, 'INVALID_CHALLENGE');
            }
          },
        ),
        { numRuns: 50 },
      );
    });
  });

  // -----------------------------------------------------------------
  // Family 4: computeProof invalid password → INVALID_PASSWORD
  // -----------------------------------------------------------------
  // Validation source: `assertUint8Array(password, 'INVALID_PASSWORD',
  // 'password')` followed by
  // `assertUint8ArrayLengthBetween(password, 0, 4096, 'INVALID_PASSWORD',
  // 'password')` in src/compute-proof.ts. Invalid family = non-
  // Uint8Array OR length > 4096. Length 0 IS valid per Requirement
  // 3.7 and is intentionally NOT generated by `arbInvalidPasswordShape`.
  describe('4. computeProof invalid password → INVALID_PASSWORD', () => {
    it('throws on wrong type or oversize password', () => {
      fc.assert(
        fc.property(
          arbValidPrivateKey32,
          arbInvalidPasswordShape,
          arbValidChallenge32,
          (privateKey, password, challenge) => {
            try {
              computeProof(privateKey, password as Uint8Array, challenge);
              throw new Error('Expected throw, got success');
            } catch (e) {
              expectInvalidInputError(e, 'INVALID_PASSWORD');
            }
          },
        ),
        { numRuns: 50 },
      );
    });
  });

  // -----------------------------------------------------------------
  // Family 5: verifyProof invalid publicKey → INVALID_PUBLIC_KEY
  // -----------------------------------------------------------------
  // Three sub-cases per Requirement 4.5:
  //   5a. wrong shape/length (non-Uint8Array or length ≠ 32)
  //   5b. non-decodable bytes (Uint8Array(32) that fails Edwards
  //       point decoding — caught by `pointFromBytesStrict`'s
  //       re-wrap to `InvalidInputError('INVALID_PUBLIC_KEY', ...)`)
  //   5c. identity-point encoding (decodes to `O = (0, 1)`, rejected
  //       by the explicit `PK.is0()` check — see Requirement 4.5
  //       file-header rationale on why accepting identity would
  //       trivially break soundness)
  describe('5. verifyProof invalid publicKey → INVALID_PUBLIC_KEY', () => {
    it('throws on wrong shape or wrong length', () => {
      fc.assert(
        fc.property(
          arbInvalidPublicKeyShape,
          arbValidPrivateKey32,
          arbValidPassword,
          arbValidChallenge32,
          (publicKey, privateKey, password, challenge) => {
            // Build a well-formed honest proof under the valid
            // privateKey so the verify path's failure mode is
            // isolated to the publicKey shape check.
            const proof = buildHonestProof(privateKey, password, challenge);
            try {
              verifyProof(publicKey as Uint8Array, challenge, proof);
              throw new Error('Expected throw, got success');
            } catch (e) {
              expectInvalidInputError(e, 'INVALID_PUBLIC_KEY');
            }
          },
        ),
        { numRuns: 50 },
      );
    });

    it('throws on non-decodable bytes (Uint8Array(32) that is not a valid Edwards point)', () => {
      fc.assert(
        fc.property(
          arbNonDecodablePublicKey,
          arbValidPrivateKey32,
          arbValidPassword,
          arbValidChallenge32,
          (publicKey, privateKey, password, challenge) => {
            const proof = buildHonestProof(privateKey, password, challenge);
            try {
              verifyProof(publicKey, challenge, proof);
              throw new Error('Expected throw, got success');
            } catch (e) {
              expectInvalidInputError(e, 'INVALID_PUBLIC_KEY');
            }
          },
        ),
        { numRuns: 50 },
      );
    });

    it('throws on identity-point encoding', () => {
      // Identity-point rejection is the ONE case that can succeed at
      // shape AND decode but still fail validation. The explicit
      // `PK.is0()` check in verify-proof.ts step 2-identity catches
      // it; without that check, accepting `publicKey = O` would let
      // any forger satisfy the verification equation (see file
      // header). Requirement 4.5 specifically calls out this case.
      fc.assert(
        fc.property(
          arbIdentityPublicKey,
          arbValidPrivateKey32,
          arbValidPassword,
          arbValidChallenge32,
          (publicKey, privateKey, password, challenge) => {
            const proof = buildHonestProof(privateKey, password, challenge);
            try {
              verifyProof(publicKey, challenge, proof);
              throw new Error('Expected throw, got success');
            } catch (e) {
              expectInvalidInputError(e, 'INVALID_PUBLIC_KEY');
            }
          },
        ),
        { numRuns: 10 },
      );
    });
  });

  // -----------------------------------------------------------------
  // Family 6: verifyProof invalid proof shape → INVALID_PROOF
  // -----------------------------------------------------------------
  // Validation source: `assertUint8ArrayLength(proof, 64,
  // 'INVALID_PROOF', 'proof')` in src/verify-proof.ts. Invalid family
  // = non-Uint8Array OR length ≠ 64. THIS family is concerned ONLY
  // with shape — the "well-formed-but-mathematically-invalid proof"
  // case (malformed `R`, out-of-range `s`) is locked separately by
  // Property 9, which asserts those cases return `false` rather than
  // throw. publicKey and challenge are well-formed by construction
  // so `INVALID_PROOF` is the only failure mode reachable.
  describe('6. verifyProof invalid proof shape → INVALID_PROOF', () => {
    it('throws on non-Uint8Array or wrong length', () => {
      fc.assert(
        fc.property(
          arbValidPrivateKey32,
          arbValidChallenge32,
          arbInvalidProofShape,
          (privateKey, challenge, proof) => {
            const publicKey = derivePublicKey(privateKey);
            try {
              verifyProof(publicKey, challenge, proof as Uint8Array);
              throw new Error('Expected throw, got success');
            } catch (e) {
              expectInvalidInputError(e, 'INVALID_PROOF');
            }
          },
        ),
        { numRuns: 50 },
      );
    });
  });
});
