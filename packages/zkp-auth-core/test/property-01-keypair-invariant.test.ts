// @zkp-auth/core — Property 1: Key pair structural invariant
//
// Property 1: Key pair structural invariant
// Validates: Requirements 1.1, 1.2, 1.3, 11.2
// See design.md → "Correctness Properties → Property 1" and
//     design.md → "Components and Interfaces → keypair.ts".
//
// For any invocation of `generateKeyPair()`, the returned object satisfies
// all of the following:
//
//   * `privateKey` is a `Uint8Array` of length 32;
//   * `publicKey` is a `Uint8Array` of length 32;
//   * the little-endian decoding of `privateKey` is a scalar `n` with
//     `1 <= n < L` (where `L = ed25519.Point.Fn.ORDER`);
//   * `publicKey` byte-equals the canonical 32-byte encoding of
//     `n · BasePoint`.
//
// `fast-check` drives the property over 100 invocations. Because
// `generateKeyPair()` takes no arguments, we use `fc.constant(null)` as
// the (unused) input arbitrary so the property body is re-run `numRuns`
// times against the LIVE Node CSPRNG. We deliberately stick with the
// `fc.assert(fc.property(...), { numRuns: 100 })` pattern even when there
// are no inputs, to align with later property files (Property 6
// round-trip, Property 7 tampering, etc.) that DO have generated inputs.
//
// Per-byte numeric equality (`expectedPubBytes[i] !== publicKey[i]`) on
// these `Uint8Array` views is fine in test files: byte values are
// numbers in `[0, 255]`, not secret material, and the audit guard from
// task 13.1 scans `src/**/*.ts` only — `test/**/*.ts` is explicitly out
// of its scope.

import { describe, it } from 'vitest';
import fc from 'fast-check';

import { generateKeyPair } from '../src/keypair.js';
import { L, scalarFromBytesLE, pointToBytes, BASE } from '../src/encoding.js';

describe('Property 1: Key pair structural invariant', () => {
  it('every emitted key pair satisfies length, range, and pubkey-derivation invariants', () => {
    fc.assert(
      fc.property(fc.constant(null), () => {
        const { privateKey, publicKey } = generateKeyPair();

        // Structural assertions on `privateKey` (Requirement 1.1).
        if (!(privateKey instanceof Uint8Array)) return false;
        if (privateKey.length !== 32) return false;

        // Structural assertions on `publicKey` (Requirement 1.1).
        if (!(publicKey instanceof Uint8Array)) return false;
        if (publicKey.length !== 32) return false;

        // Scalar-range assertion: `n = int_LE(privateKey)` lies in
        // `[1, L)` (Requirements 1.2, 11.2). `scalarFromBytesLE`
        // delegates to `bytesToNumberLE` from `@noble/curves/utils.js`
        // and performs no reduction, so this is the raw little-endian
        // decoding the requirement refers to.
        const n = scalarFromBytesLE(privateKey);
        if (!(n >= 1n && n < L)) return false;

        // Pubkey-derivation assertion: `publicKey == encode(n · G)`
        // (Requirements 1.3, 11.2). We compute the expected encoding
        // from the same `n` decoded above and assert byte-for-byte
        // equality with the returned `publicKey`.
        const expectedPubBytes = pointToBytes(BASE.multiply(n));
        if (expectedPubBytes.length !== publicKey.length) return false;
        for (let i = 0; i < expectedPubBytes.length; i += 1) {
          if (expectedPubBytes[i] !== publicKey[i]) return false;
        }

        return true;
      }),
      { numRuns: 100 },
    );
  });
});
