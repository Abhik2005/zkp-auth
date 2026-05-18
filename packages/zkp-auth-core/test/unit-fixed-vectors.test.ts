// @zkp-auth/core — byte-exact fixed-vector regression test
//
// Validates: Requirements 8.1, 9.3 (deterministic-vector test)
//
// This file is the byte-for-byte regression lock on the entire
// Fiat-Shamir transcript and proof-construction pipeline of
// `compute-proof.ts`. It freezes a small hand-picked table of
// `(privateKey_hex, password, challenge_hex, mocked_nonce_hex,
// expected_proof_hex)` quintuples, recomputes each proof from the
// implementation via `__forTesting__.computeProofWithFixedNonce`,
// and asserts byte-equality against the frozen `expected_proof_hex`
// value. Any future change to ANY step of the construction —
//
//   - the Fiat-Shamir transcript byte ordering
//     (`R_bytes || publicKey_bytes || challenge_bytes`,
//     Requirement 8.1, design "Components and Interfaces →
//     transcript.ts"),
//   - the SHA-512 wide-reduction strategy
//     (`int_LE(SHA-512(96 bytes)) mod L`, Requirement 8.2),
//   - the response-scalar formula
//     (`s = (r + c · x) mod L`, Requirement 3.4),
//   - the canonical RFC 8032 encodings of `R` and `publicKey`,
//   - the little-endian encoding of `s`,
//   - or the assembly order `proof = R_bytes || s_bytes`
//     (Requirement 3.1)
//
// — would change at least one frozen byte and trip this test. That
// is the regression-protection contract Requirement 9.3
// ("deterministic-vector test") demands of the deterministic side
// of the test suite.
//
// VECTORS
//
// Three vectors are frozen, exercising the structural extremes of
// the `password` length window (`[0, 4096]` per Requirement 3.7):
//
//   (a) vanilla        — 32-byte deterministic password pattern,
//                        random-looking PRIVATE_KEY and CHALLENGE.
//   (b) empty password — `password.length === 0` (the lower bound
//                        of the valid-shape window).
//   (c) max password   — `password.length === 4096` (the upper
//                        bound of the valid-shape window), filled
//                        with the deterministic byte `0x55` so the
//                        4096-byte payload is reproducible from a
//                        single-line constructor without bloating
//                        this test file with 8192 hex characters.
//
// All three vectors share the same fixed `(PRIVATE_KEY_HEX,
// CHALLENGE_HEX, NONCE_HEX)` triple. This is intentional: per
// Requirements 3.3 / 11.1 / Property 10, `password` is reserved-
// but-unused metadata — it does NOT participate in scalar
// derivation and is NOT part of the Fiat-Shamir transcript.
// Therefore vectors (a), (b), and (c) MUST produce byte-identical
// proofs even though their `password` lengths differ across the
// full `[0, 4096]` range. The shared expected-proof-hex value
// `EXPECTED_PROOF_HEX_ABC` below makes that contract a single
// regression target — a future implementation change that quietly
// folded `password` into the proof would diverge vector (a)'s
// output from vector (b)'s, and at least one of the three
// `expect(...).toBe(EXPECTED_PROOF_HEX_ABC)` assertions would
// fail. This is the deterministic dual of Property 10's
// generative no-op claim.
//
// HOW THE FROZEN HEX WAS GENERATED
//
// The frozen value of `EXPECTED_PROOF_HEX_ABC` was computed ONCE,
// from the very implementation under test, by running each of the
// three input quintuples through
// `__forTesting__.computeProofWithFixedNonce(...)` and capturing
// `bytesToHex(proof)`. The generator was a throwaway
// vitest file (`__tmp_generate_vectors.test.ts`) that produced
// the hex strings on stdout via `console.log` and was deleted
// immediately after capture. No generator script remains in the
// package — only the frozen output below. To re-derive the value
// (e.g. after a deliberate, reviewed change to the construction),
// re-run the same procedure: write a temporary test that calls
// `__forTesting__.computeProofWithFixedNonce` with the inputs
// below and prints `bytesToHex(proof)`, paste the new hex back into
// `EXPECTED_PROOF_HEX_ABC`, delete the temporary file. Reviewers of
// such a change MUST treat the new value as a protocol-level
// commitment and audit the diff against Requirements 8.1–8.4.
//
// VALIDATION OF CHOSEN INPUTS
//
// PRIVATE_KEY: little-endian decoding `0x0eecdab8967452301efcdab8...01`
//   = `0xecdab8967452301efcdab8967452301efcdab8967452301efcdab896745
//      2301`. This value is in `[1, L)` (verified during vector
//   generation; `L > 2^252` and the chosen scalar is just under
//   `2^252`), so `compute-proof.ts` step 2 (Requirement 3.5) does
//   not throw. The terminal byte is `0x0e` rather than the
//   "obvious" `0xef` to keep the high bits below `L`'s leading
//   byte.
//
// NONCE: little-endian decoding produces a non-zero scalar in
//   `[1, L)` (verified during vector generation). The
//   `__forTesting__` hook validates this contract too — see its
//   "throws InvalidInputError on r_bytes reducing to 0n" branch in
//   `compute-proof.ts`. The chosen NONCE is well clear of `L` so
//   no overflow concerns apply.
//
// CHALLENGE: any 32 bytes are structurally valid (Requirement 3.6
//   says only that the shape must be `Uint8Array(32)`); the
//   verifier-chosen randomness in production comes from
//   `generateChallenge`'s CSPRNG draw, but the deterministic
//   pattern below is fine for a regression vector.
//
// PER-BYTE NUMERIC EQUALITY IS FINE IN THIS FILE
//
// This file is under `test/` and is NOT scanned by the audit guard
// (task 13.1, which scans `src/**/*.ts` only). Per-byte construction
// of `Uint8Array.fill(...)` and string-equality on hex strings via
// `toBe(...)` are permitted here — none of them touches secret
// material at runtime.
//
// See design.md → "Correctness Properties → Property 10" (the
//     generative-test sibling of vectors (a)/(b)/(c)),
//     design.md → "Components and Interfaces → compute-proof.ts"
//     (specifically the `__forTesting__` hook contract pinning the
//     nonce input), and
//     requirements.md → "Requirement 3", "Requirement 8",
//     "Requirement 9.3", "Requirement 11".

import { describe, it, expect } from 'vitest';
import { hexToBytes, bytesToHex } from '@noble/curves/utils.js';

import { __forTesting__ } from '../src/compute-proof.js';

// ---------------------------------------------------------------------
// Shared inputs across all three vectors
// ---------------------------------------------------------------------

/**
 * 32-byte little-endian encoding of a hand-picked `privateKey` whose
 * scalar decoding lies in `[1, L)`. Picked deterministically rather
 * than randomly so a reader can re-derive the scalar by hand if
 * needed: the hex pattern `01 23 45 67 89 ab cd ef ...` repeats four
 * times with the final byte adjusted from `0xef` to `0x0e` to keep
 * the high-end of the little-endian decoding strictly below `L`.
 */
const PRIVATE_KEY_HEX =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd0e';

/**
 * 32-byte mocked nonce. Decodes to a non-zero scalar in `[1, L)`,
 * satisfying both
 * `__forTesting__.computeProofWithFixedNonce`'s "well-formed
 * `r_bytes` of exactly 32 bytes whose `mod L` reduction is
 * non-zero" contract and the requirement that the regression
 * vectors be reproducible.
 */
const NONCE_HEX =
  'c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec00f';

/**
 * 32-byte deterministic verifier challenge. Any 32-byte buffer is
 * structurally valid for `computeProof` (Requirement 3.6); the
 * pattern `feedface` is repeated to keep the value humanly
 * recognisable in test output.
 */
const CHALLENGE_HEX =
  'feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfac0';

/**
 * Frozen 64-byte proof `R_bytes || s_bytes` shared by all three
 * vectors. Generated ONCE from the implementation under test using
 * `__forTesting__.computeProofWithFixedNonce` against the
 * `(PRIVATE_KEY_HEX, password, CHALLENGE_HEX, NONCE_HEX)` quintuple
 * — and identical across the three `password` choices because
 * `password` is a no-op on the produced proof per Requirements 3.3
 * / 11.1 / Property 10.
 *
 * Any future change that diverges this byte string is a change to
 * the protocol's wire output and MUST be reviewed as such.
 */
const EXPECTED_PROOF_HEX_ABC =
  '7095b380957b79335491d006971446114bed9ffec36fbf3a8f11dc16e1c991c5' +
  'da73c19f196b89a2e2da5af28b0c85acb53888127c00d561c92e0d92ea171e0c';

// ---------------------------------------------------------------------
// Vectors
// ---------------------------------------------------------------------

describe('byte-exact fixed-vector regression', () => {
  it('vector (a) vanilla: 32-byte deterministic password produces frozen proof', () => {
    // Deterministic 32-byte password constructed from the affine
    // pattern `(i * 7 + 3) mod 256` so the buffer is reproducible
    // from this single line of code rather than committed as 64
    // hex characters. The exact bytes do not matter for the test
    // because `password` is a no-op on the proof output, but the
    // pattern is fixed so anyone re-deriving the vector lands on
    // the same buffer this file was generated against.
    const password = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) {
      password[i] = (i * 7 + 3) & 0xff;
    }

    const proof = __forTesting__.computeProofWithFixedNonce(
      hexToBytes(PRIVATE_KEY_HEX),
      password,
      hexToBytes(CHALLENGE_HEX),
      hexToBytes(NONCE_HEX),
    );

    expect(proof).toBeInstanceOf(Uint8Array);
    expect(proof.length).toBe(64);
    expect(bytesToHex(proof)).toBe(EXPECTED_PROOF_HEX_ABC);
  });

  it('vector (b) password.length === 0: empty password produces frozen proof', () => {
    // Empty password is the lower bound of the valid-shape window
    // per Requirement 3.7. The vector locks that
    // `assertUint8ArrayLengthBetween(password, 0, 4096, ...)`
    // accepts length 0 and that the produced proof is byte-identical
    // to vector (a)'s — i.e. `password` did not influence the
    // construction.
    const password = new Uint8Array(0);

    const proof = __forTesting__.computeProofWithFixedNonce(
      hexToBytes(PRIVATE_KEY_HEX),
      password,
      hexToBytes(CHALLENGE_HEX),
      hexToBytes(NONCE_HEX),
    );

    expect(proof).toBeInstanceOf(Uint8Array);
    expect(proof.length).toBe(64);
    expect(bytesToHex(proof)).toBe(EXPECTED_PROOF_HEX_ABC);
  });

  it('vector (c) password.length === 4096: max-length password produces frozen proof', () => {
    // Max-length password is the upper bound of the valid-shape
    // window per Requirement 3.7. Filled with the deterministic
    // byte `0x55` (binary `01010101`) so the 4096-byte payload is
    // reproducible from a single-line constructor without
    // committing 8192 hex characters to this test file. The
    // expected proof is the same `EXPECTED_PROOF_HEX_ABC` because
    // `password` does not influence the construction — the
    // 4096-byte vs. 0-byte vs. 32-byte payloads in vectors
    // (a)/(b)/(c) all collapse to the same proof byte string.
    const password = new Uint8Array(4096).fill(0x55);

    const proof = __forTesting__.computeProofWithFixedNonce(
      hexToBytes(PRIVATE_KEY_HEX),
      password,
      hexToBytes(CHALLENGE_HEX),
      hexToBytes(NONCE_HEX),
    );

    expect(proof).toBeInstanceOf(Uint8Array);
    expect(proof.length).toBe(64);
    expect(bytesToHex(proof)).toBe(EXPECTED_PROOF_HEX_ABC);
  });
});
