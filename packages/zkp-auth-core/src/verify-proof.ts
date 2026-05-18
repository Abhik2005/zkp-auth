// @zkp-auth/core — Schnorr proof verification with Fiat-Shamir transform
//
// This module implements the sole proof-verification entry point of
// `@zkp-auth/core`. Given a registered `publicKey`, a verifier-chosen
// `challenge`, and a candidate 64-byte `proof` produced by
// `compute-proof.ts`, it returns `true` iff the proof satisfies the
// non-interactive Schnorr verification equation
//
//   s · G == R + c · publicKey
//
// where `R || s = proof` (32 bytes each), `G = BASE`, and `c` is the
// Fiat-Shamir scalar pinned in `transcript.ts`:
//
//   c = int_LE(SHA-512(R_bytes || publicKey_bytes || challenge_bytes)) mod L
//
// The verification equation is symmetric to the construction in
// `compute-proof.ts`: substituting `s = r + c · x` and `R = r · G` and
// `publicKey = x · G` gives `(r + c·x) · G == r·G + c · (x·G)`, which
// holds in the Edwards group. Round-trip correctness against
// `compute-proof.ts` is locked by Property 6, and soundness against a
// matching-key forger is locked by Property 8 (cross-key rejection).
//
// Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9,
//            4.10, 4.11
// See design.md → "Components and Interfaces → verify-proof.ts" and
//     design.md → "Key design decisions → 4" (constant-time multiply
//                                              on the verify side too)
//                                          → 5 (asymmetric error model)
//                                          → 6 (oracle avoidance via
//                                              `timingSafeEqualBytes`)
//                                          → "Verification equation
//                                              choice" and
//     requirements.md → "Requirement 4: Proof Verification".
//
// SECURITY-CRITICAL CONTRACTS:
//
// 1. Asymmetric error model (Requirement 4.5–4.8, design "Key design
//    decisions → 5"). The verify path distinguishes two classes of
//    fault:
//
//      • Caller-side faults — `publicKey` shape/decode/identity-point,
//        `challenge` shape, `proof` shape. These represent integration
//        errors against the verifier's own state (an unregistered
//        public key, a challenge that the verifier itself did not
//        produce, a proof whose length is structurally wrong) and
//        MUST surface as `InvalidInputError` with a stable `.code`
//        so the caller can pattern-match and remediate.
//
//      • Attacker-controlled proof material — malformed `R_bytes`
//        (cannot decode to an Edwards point, Requirement 4.7),
//        out-of-range `s` with `s >= L` (Requirement 4.8). These
//        represent a tampered or hostile proof submitted by a
//        prover-side adversary. The verify path MUST silently return
//        `false` here, NOT throw — throwing would expose an oracle
//        that distinguishes "malformed proof" from "well-formed but
//        mathematically invalid proof", giving an attacker a free
//        bit of information per submission. Property 9
//        (test/property-09-malformed-r-out-of-range-s.test.ts) locks
//        the silent-`false` half of this contract.
//
// 2. `timingSafeEqualBytes` over `point.equals` (Requirement 4.4,
//    design "Key design decisions → 6"). The final equation check
//    `lhs == rhs` MUST be performed by encoding both points to bytes
//    via `pointToBytes` and comparing those bytes through
//    `timingSafeEqualBytes`. The `EdwardsPoint.equals` method works
//    in extended projective coordinates (it cross-multiplies the `Z`
//    components), and its timing profile is data-dependent on the
//    field arithmetic involved. A timing oracle on the verify
//    equation could let an adversary distinguish "almost-correct"
//    proofs from totally-wrong ones, weakening soundness in
//    multi-attempt scenarios. Encoding to canonical RFC 8032 bytes
//    and constant-time-comparing is the standard mitigation; it
//    also locks the comparison to the same canonical encoding the
//    Fiat-Shamir transcript uses, removing any mismatch between
//    "equal as projective points" and "equal as wire bytes".
//
// 3. `pointFromBytesStrict` for `publicKey` (caller-side throw) vs.
//    `pointFromBytesSoft` for `R_bytes` (silent false). These two
//    decode helpers in `encoding.ts` are NOT interchangeable on this
//    code path. The strict variant re-throws as `CryptoError`, which
//    we re-wrap into `InvalidInputError('INVALID_PUBLIC_KEY', ...)`
//    per Requirement 4.5; the soft variant returns `null`, which we
//    convert into `false` per Requirement 4.7. Mixing them up would
//    invert the error model for that input — a `pointFromBytesSoft`
//    on `publicKey` would silently return `false` for an
//    un-decodable public key (denying the caller the typed error),
//    and a `pointFromBytesStrict` on `R_bytes` would throw on any
//    tampered proof (creating exactly the oracle Requirement 4.7
//    forbids).
//
// 4. `is0()` rejection of identity `publicKey` (Requirement 4.5).
//    The Edwards identity point `O = (0, 1)` is a valid encoding —
//    `pointFromBytesStrict` returns it without complaint — but
//    accepting `publicKey == O` would let any forger trivially win:
//    with `publicKey = O`, the verification equation collapses to
//    `s · G == R + c · O = R`, so any `(R, s)` pair satisfying
//    `s · G == R` verifies regardless of `c`. The forger can pick
//    any scalar `s`, set `R = s · G`, and submit `(R, s)` for any
//    challenge. We close this attack at the verifier by rejecting
//    `publicKey = O` outright via `PK.is0()` after a successful
//    decode. The check uses the `is0()` method that
//    `EdwardsPoint extends CurvePoint<bigint, EdwardsPoint>`
//    inherits from the `CurvePoint` interface in
//    `@noble/curves/abstract/curve.d.ts` — confirmed available on
//    every concrete Edwards point in noble v1.9.x.
//
// 5. NO `===` / `!==` / `Buffer.equals` on byte arrays anywhere in
//    this file. The only `===` / `!==` operators present are on
//    sentinel and bigint values:
//
//      • `R === null` — sentinel check on the soft-decode result;
//        `null` is not a byte array, so this is permitted.
//      • `s >= L` and `s === 0n` — bigint range checks; bigint
//        comparisons are permitted under Requirement 3.8 (the
//        forbidden-data identifier set is byte arrays only).
//
//    Every byte-array equality in the verify path runs through
//    `timingSafeEqualBytes` from `compare.ts`. The audit guard in
//    task 13.1 enforces this constraint by string-matching against
//    the forbidden-data identifier set across `src/**/*.ts`.

import { InvalidInputError } from './errors.js';
import { assertUint8ArrayLength } from './validate.js';
import {
  L,
  BASE,
  scalarFromBytesLE,
  pointFromBytesStrict,
  pointFromBytesSoft,
  pointToBytes,
} from './encoding.js';
import { computeFiatShamirScalar } from './transcript.js';
import { timingSafeEqualBytes } from './compare.js';

/**
 * Verifies a 64-byte Schnorr proof against the registered `publicKey`
 * and the verifier-chosen `challenge`.
 *
 * Returns `true` iff `proof = R_bytes || s_bytes` satisfies the
 * non-interactive Schnorr equation
 *
 *   s · G == R + c · publicKey
 *
 * with `c = int_LE(SHA-512(R_bytes || publicKey || challenge)) mod L`
 * (the Fiat-Shamir scalar pinned in `transcript.ts`, identical to the
 * one used by `compute-proof.ts`).
 *
 * Failure modes:
 *
 * - `InvalidInputError` with `code === 'INVALID_PUBLIC_KEY'` —
 *   `publicKey` is not a `Uint8Array(32)` (Requirement 4.5), OR it
 *   fails to decode as an Edwards point, OR it decodes to the
 *   identity point `O = (0, 1)`. The identity-point rejection is the
 *   one Requirement 4.5 specifically calls out: with `publicKey = O`,
 *   the verification equation collapses to `s · G == R`, which any
 *   forger can satisfy by picking any `s` and setting `R = s · G`.
 * - `InvalidInputError` with `code === 'INVALID_CHALLENGE'` —
 *   `challenge` is not a `Uint8Array(32)` (Requirement 4.6).
 * - `InvalidInputError` with `code === 'INVALID_PROOF'` — `proof` is
 *   not a `Uint8Array(64)` (Requirement 4.6, applied to the proof
 *   shape).
 * - Returns `false` (does NOT throw) when:
 *     • `R_bytes` does not decode to a valid Edwards point
 *       (Requirement 4.7), OR
 *     • `s = int_LE(s_bytes) >= L` (Requirement 4.8), OR
 *     • the verification equation `s · G != R + c · publicKey` does
 *       not hold (Requirement 4.9, the standard "wrong proof"
 *       rejection).
 *
 *   The silent-`false` returns are deliberate (design "Key design
 *   decisions → 5–6"): the verify path must NOT distinguish between
 *   "malformed proof material" and "well-formed but mathematically
 *   invalid proof" via thrown errors, since that would expose an
 *   oracle to a prover-side adversary.
 *
 * @param publicKey 32-byte Ed25519 point encoding of the registered
 *   public key. Must decode to a non-identity point.
 * @param challenge 32-byte verifier-chosen challenge, ideally
 *   produced by `generateChallenge`.
 * @param proof     64-byte proof `R_bytes || s_bytes` produced by
 *   `compute-proof.ts`.
 * @returns `true` iff the proof satisfies the Schnorr verification
 *   equation under `(publicKey, challenge)`; `false` for any
 *   well-typed-but-invalid proof or attacker-tampered proof material.
 * @throws InvalidInputError When any caller-supplied input fails
 *   shape, length, decoding, or identity-point validation.
 */
export function verifyProof(
  publicKey: Uint8Array,
  challenge: Uint8Array,
  proof: Uint8Array,
): boolean {
  // Step 1 — input shape validation (Requirements 4.5, 4.6).
  // Length checks come first so every subsequent step can rely on
  // the inputs being byte arrays of the right size. The error codes
  // here are the public, stable identifiers callers are expected to
  // pattern-match on (Requirement 7.4).
  assertUint8ArrayLength(publicKey, 32, 'INVALID_PUBLIC_KEY', 'publicKey');
  assertUint8ArrayLength(challenge, 32, 'INVALID_CHALLENGE', 'challenge');
  assertUint8ArrayLength(proof, 64, 'INVALID_PROOF', 'proof');

  // Step 2 — strict publicKey decode (Requirement 4.5).
  // `pointFromBytesStrict` throws `CryptoError` on any decode
  // failure (invalid encoding, off-curve y-coordinate, non-canonical
  // representation, etc.). We catch and re-throw as the more-
  // specific `InvalidInputError('INVALID_PUBLIC_KEY', ...)` so the
  // caller-facing error taxonomy stays closed at the public boundary
  // (Requirement 7.5). The original `CryptoError` is attached as
  // `cause` via the standard `Error` `{ cause }` mechanism — the
  // `InvalidInputError` constructor in `errors.ts` does NOT accept
  // an options bag (it is `(code, message)` only), but `Error` itself
  // honors `.cause` if assigned post-construction. Rather than rely
  // on that less-portable assignment, we fold the underlying error's
  // message into the human-readable `message` text — the message is
  // for diagnostics only (Requirement 7.4 explicitly tells callers
  // not to parse it), so embedding the cause is safe.
  let PK;
  try {
    PK = pointFromBytesStrict(publicKey);
  } catch (e) {
    throw new InvalidInputError(
      'INVALID_PUBLIC_KEY',
      `publicKey: failed to decode as Edwards point (${(e as Error).message})`,
    );
  }

  // Identity-point rejection (Requirement 4.5, SECURITY-CRITICAL
  // CONTRACT 4 above). `is0()` is the `CurvePoint`-interface method
  // that returns `true` for the Edwards identity `O = (0, 1)` and
  // `false` for every other point. Without this check, a registered
  // `publicKey == O` would let any forger satisfy the verification
  // equation by picking any `s` and setting `R = s · G`.
  if (PK.is0()) {
    throw new InvalidInputError(
      'INVALID_PUBLIC_KEY',
      'publicKey decodes to the identity point',
    );
  }

  // Step 3 — slice the proof into its `R` and `s` components per
  // the encoding contract (Requirement 3.1, mirrored on the verify
  // side as Requirement 4.6). `subarray` returns views into the
  // caller's `proof` buffer — no copy is made — which is fine for
  // every downstream operation here: `pointFromBytesSoft` and
  // `scalarFromBytesLE` both read-only-consume their argument,
  // and `computeFiatShamirScalar` likewise only reads `R_bytes`.
  const R_bytes = proof.subarray(0, 32);
  const s_bytes = proof.subarray(32, 64);

  // Step 4 — soft `R` decode (Requirement 4.7).
  // `pointFromBytesSoft` returns `null` instead of throwing when the
  // bytes cannot decode to a valid Edwards point. Per Requirement
  // 4.7, the verify path MUST surface this as a silent `false` — a
  // throw here would create a timing/exception oracle that
  // distinguishes "malformed `R`" from "well-formed but invalid
  // proof", giving an adversary a free bit per submission.
  //
  // The `R === null` comparison is on a sentinel value, not on a
  // byte array, so it is permitted under the Requirement 3.8
  // forbidden-data-identifier set.
  const R = pointFromBytesSoft(R_bytes);
  if (R === null) {
    return false;
  }

  // Step 5 — out-of-range `s` rejection (Requirement 4.8).
  // `scalarFromBytesLE` decodes the 32-byte little-endian buffer as
  // a non-negative bigint in `[0, 2^256)`. Per Requirement 4.8, any
  // `s >= L` MUST cause `verifyProof` to return `false` silently —
  // again to deny an oracle distinguishing "out-of-range `s`" from
  // "in-range but mathematically invalid `s`". `s === 0n` is in
  // range and is NOT rejected here (a degenerate but well-formed
  // value); the verification equation will reject it via the
  // mathematical check downstream if it does not happen to satisfy
  // `0 == R + c · publicKey`.
  //
  // The `s >= L` and `s === 0n`-not-rejected comparisons are on
  // bigint values, not byte arrays, so they are permitted.
  const s = scalarFromBytesLE(s_bytes);
  if (s >= L) {
    return false;
  }

  // Step 6 — Fiat-Shamir scalar (Requirement 4.3, 8.1, 8.2).
  // Uses the SAME `computeFiatShamirScalar` function the prover
  // calls in `compute-proof.ts`. Sharing the single transcript
  // implementation across prover and verifier — pinned in
  // `transcript.ts` — is what guarantees the construction cannot
  // drift between the two sides; any change to the hash input,
  // ordering, or reduction strategy lands in both halves
  // simultaneously.
  const c = computeFiatShamirScalar(R_bytes, publicKey, challenge);

  // Step 7 — assemble the two sides of the verification equation
  // `s · G == R + c · publicKey` (Requirement 4.3, 4.4).
  //
  // `BASE.multiply(s)` uses the constant-time scalar-multiply ladder.
  // `s` here is NOT a secret — it travels over the wire — but
  // Requirement 4.4 mandates that the verify equation use the same
  // primitive throughout, and `multiply` is also the only ladder
  // available on the public `EdwardsPoint` API in noble v1.9.x that
  // we use uniformly across the codebase. There is no compensating
  // performance argument for `multiplyUnsafe` here on the verifier
  // side — keeping the call uniform with `compute-proof.ts` makes
  // the audit surface a single rule rather than two.
  //
  // `PK.multiply(c)` likewise uses the constant-time ladder; `c` is
  // derived from a public hash and is also non-secret, but the
  // uniformity argument applies equally.
  //
  // `R.add(...)` is the standard Edwards group addition.
  const lhs = BASE.multiply(s);
  const rhs = R.add(PK.multiply(c));

  // Step 8 — constant-time equation check (Requirement 4.4,
  // SECURITY-CRITICAL CONTRACT 2 above). Encode both points to their
  // canonical 32-byte RFC 8032 representations and compare via
  // `timingSafeEqualBytes`. We MUST NOT use `lhs.equals(rhs)` — that
  // method works in extended projective coordinates and its timing
  // profile is data-dependent on the field arithmetic involved.
  //
  // The byte-level comparison also pins the equality semantics to
  // "equal as wire bytes", which is the same equality the
  // Fiat-Shamir transcript already commits to via `pointToBytes(R)`.
  // No mismatch between "equal as projective points" and "equal as
  // canonical encodings" is possible at this seam.
  return timingSafeEqualBytes(pointToBytes(lhs), pointToBytes(rhs));
}
