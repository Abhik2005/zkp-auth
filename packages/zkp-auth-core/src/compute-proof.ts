// @zkp-auth/core — Schnorr proof construction with Fiat-Shamir transform
//
// This module implements the sole proof-construction entry point of
// `@zkp-auth/core`. Given a `privateKey`, a (reserved-but-unused)
// `password`, and a verifier-chosen `challenge`, it produces the
// 64-byte Schnorr proof `R || s` whose verification equation
// `s · G == R + c · publicKey` is exercised on the verifier side
// by `verify-proof.ts` (Requirement 4.3, round-trip Property 6).
//
// The construction follows the textbook non-interactive Schnorr
// identification scheme with the Fiat-Shamir transform pinned in
// `transcript.ts`:
//
//   x = int_LE(privateKey)                     -- secret scalar
//   r ←$ [1, L)                                -- fresh CSPRNG nonce
//   R = r · G                                  -- commitment
//   c = int_LE(SHA-512(R || X || challenge)) mod L
//   s = (r + c · x) mod L                      -- response
//   proof = R_bytes || s_bytes                 -- 64 bytes
//
// where `X = x · G` is the prover's public key and `||` is raw byte
// concatenation. `password` is intentionally absent from every step
// of this computation past the entry-level shape validation
// (Requirements 3.3, 8.1, 11.1) — see "SECURITY-CRITICAL CONTRACTS"
// below.
//
// Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8,
//            3.10, 6.1, 6.2, 6.3, 6.4, 11.1, 11.4
// See design.md → "Components and Interfaces → compute-proof.ts" and
//     design.md → "Key design decisions → 2" (rejection-sampling bound)
//                                          → 4 (constant-time `multiply`)
//                                          → "Mocking strategy" (the
//                                          `__forTesting__` hook) and
//     requirements.md → "Requirement 3: Proof Computation",
//                       "Requirement 6: Non-Functional — Fresh Nonces",
//                       "Requirement 11: Password-to-Scalar Derivation".
//
// SECURITY-CRITICAL CONTRACTS:
//
// 1. `password` is reserved-but-unused (Requirement 11.1, 11.3). After
//    the entry-level shape validation it is NEVER read. It is NOT
//    mixed into the scalar `x`, NOT folded into the Fiat-Shamir
//    transcript (the call to `computeFiatShamirScalar` does not even
//    accept a `password` parameter — see `transcript.ts`'s file-level
//    closure of the construction), and NOT touched in any computation.
//    Property 10 (test/property-10-password-no-op.test.ts) locks this
//    invariant: two distinct `password` values with the same fixed
//    nonce, `privateKey`, and `challenge` MUST produce byte-identical
//    proofs.
//
// 2. The constant-time scalar multiplication `BASE.multiply(scalar)`
//    is mandatory (design "Key design decisions → 4"). `multiplyUnsafe`
//    is FORBIDDEN anywhere a secret scalar is involved. Two call sites
//    feed secret scalars into curve math here: `BASE.multiply(x)` to
//    derive `publicKey_bytes` for the transcript, and `BASE.multiply(r)`
//    to derive the commitment `R`. Any timing variation in those
//    calls would directly leak `x` or `r` to a side-channel observer.
//
// 3. `r_bytes.fill(0)` is called inside the shared core helper after
//    the proof has been assembled, before returning (Requirement 6.4,
//    best-effort). This is memory hygiene only — JavaScript provides
//    no hard zeroization guarantee (GC may have relocated the buffer,
//    JIT may have spilled to a register), and the bigint `r` itself
//    cannot be wiped from the JS runtime. Property 15
//    (test/property-15-nonce-zero-fill.test.ts) verifies the wipe by
//    capturing a reference to the exact `Uint8Array` returned by
//    `randomBytes32()` and checking its contents post-call.
//
// 4. NO `===` / `!==` / `Buffer.equals` / short-circuit array compare
//    on any byte array derived from `privateKey`, `password`, or
//    `r_bytes` (Requirement 3.8). The only `===` / `!==` operators in
//    this file are on `bigint` values (`n_raw === 0n`, `r === 0n`,
//    `r !== 0n`) and on numeric loop counters — none of which is a
//    byte-array comparison. The audit guard in task 13.1 enforces
//    this constraint by string-matching against the forbidden-data
//    identifier set.
//
// 5. The `__forTesting__` namespace exposes a `computeProofWithFixedNonce`
//    hook that bypasses the live CSPRNG. It is annotated with the
//    audit-marker comment `// __forTesting__ — DO NOT IMPORT FROM
//    PRODUCTION CODE` immediately above the export. The audit script
//    in task 13.1 grep-asserts that this exact marker appears EXACTLY
//    ONCE in `src/`, locking the contract that no production module
//    can pull in the test-only nonce hook. The hook is NOT part of
//    the `@zkp-auth/core` public API surface and `index.ts` does NOT
//    re-export it.
//
// Implementation notes:
//
// - The bound `MAX_REJECTION_ITERATIONS = 256` matches `keypair.ts`'s
//   constant by design (design "Key design decisions → 2"). The
//   probability of `r === 0n` after a single CSPRNG draw and a
//   `mod L` reduction is `≈ 2^-252` (the only multiples of `L`
//   inside `[0, 2^256)` are `0`, `L`, `2L`, ...; very few fit), so
//   exhausting 256 successive rejections is statistically
//   indistinguishable from impossible. Exhaustion is treated as an
//   RNG anomaly and surfaced as `RandomnessError` with stable code
//   `'RNG_FAILURE'`, the same code used for an underlying CSPRNG
//   throw or short read (Requirement 3.10).
//
// - The `randomBytes32()` call site is wrapped in a try/catch that
//   re-wraps any non-`RandomnessError` into a `RandomnessError`. In
//   production this is a defense-in-depth no-op — `rng.ts` already
//   wraps every CSPRNG fault into `RandomnessError` at the chokepoint
//   — but the test suite mocks `rng.ts` directly via `vi.mock` and
//   may inject a raw `Error` (see property-13's `computeProof`
//   portion). Re-wrapping ensures the public-API contract "throw
//   only `InvalidInputError` and `RandomnessError`" holds at this
//   module's boundary regardless of what the mocked-or-real `rng.ts`
//   chooses to throw.
//
// - The shared helper `computeProofCore` takes `r` and `x` as bigints
//   already (not as bytes), so callers handle the bigint derivation
//   at the entry point and the helper concerns itself only with the
//   commitment/transcript/response/wipe/assemble pipeline. The task
//   text mentions a six-argument helper signature
//   `(privateKey, password, challenge, r_bytes, x, publicKey_bytes)`,
//   but the actual computation only NEEDS
//   `(r_bytes, r, x, publicKey_bytes, challenge)`: `privateKey` is
//   only used to derive `x`, and `password` MUST NOT participate
//   anywhere past validation (Property 10). Dropping the unused
//   parameters from the helper makes the "password is not touched
//   here" contract impossible to violate by accident, and matches
//   the same file-level-absence pattern that `transcript.ts` uses
//   for the same reason.
//
// - The `__forTesting__` hook makes a defensive COPY of the
//   caller-supplied `r_bytes` before passing it into the shared core
//   helper. The core helper zero-fills its `r_bytes` argument as part
//   of the production wipe path; if the helper wiped the test's own
//   buffer, a single test invocation that calls the hook twice with
//   the same `r_bytes` (e.g. property-10's two-call pattern, where
//   `(p1, p2)` are tested against the same nonce) would observe the
//   second call's `r` reduce to `0n` and throw. The copy keeps the
//   shared-code-path design — the helper still does the real wipe —
//   while leaving the test caller's buffer intact for re-use across
//   the property body.

import { InvalidInputError, RandomnessError } from './errors.js';
import {
  assertUint8Array,
  assertUint8ArrayLength,
  assertUint8ArrayLengthBetween,
} from './validate.js';
import { randomBytes32 } from './rng.js';
import {
  L,
  BASE,
  scalarFromBytesLE,
  scalarToBytesLE,
  reduceScalar,
  pointToBytes,
  concatBytes,
} from './encoding.js';
import { computeFiatShamirScalar } from './transcript.js';

/**
 * Maximum number of rejection-sampling iterations before treating the
 * loop as an RNG anomaly. Locked at 256 by design.md "Key design
 * decisions → 2" — the same constant `keypair.ts` uses for its
 * private-key acceptance loop. See the file-header comment for the
 * statistical justification.
 */
const MAX_REJECTION_ITERATIONS = 256;

/**
 * Shared post-derivation core of the Schnorr proof construction.
 *
 * Given the bigint scalars `r ∈ [1, L)` (the nonce) and `x ∈ [1, L)`
 * (the secret), the 32-byte encoding `publicKey_bytes` of `x · G`,
 * the 32-byte `challenge`, and the 32-byte buffer `r_bytes` from
 * which `r` was derived, this helper executes design steps 5–9:
 *
 *   5. `R = BASE.multiply(r)`, `R_bytes = pointToBytes(R)`         (commitment)
 *   6. `c = computeFiatShamirScalar(R_bytes, publicKey_bytes, challenge)`
 *   7. `s = reduceScalar(r + c * x)`, `s_bytes = scalarToBytesLE(s)`
 *   8. `r_bytes.fill(0)`                                           (zero-fill)
 *   9. `return concatBytes(R_bytes, s_bytes)`                       (assembly)
 *
 * Both the public `computeProof` and the test-only
 * `__forTesting__.computeProofWithFixedNonce` route through this
 * single helper so the construction is byte-identical between the
 * two entry points. That is the property property-10's two-call
 * pattern relies on, and it is what lets property-15's RNG-mocked
 * harness observe the production wipe path through the test seam.
 *
 * `privateKey` and `password` are deliberately NOT parameters here.
 * `privateKey` was already used at the entry point to derive `x`,
 * and `password` MUST NOT participate in proof construction at all
 * (Requirement 11.1, Property 10). Closing them out at the file/function
 * level — rather than at the call site — makes the contract impossible
 * to violate by accident, mirroring the same file-level-absence
 * pattern `transcript.ts` uses to lock its own password-free contract.
 *
 * The helper performs NO byte-array equality on its inputs; it is a
 * pure curve-math + hash + concatenate pipeline. The `r_bytes.fill(0)`
 * call mutates the caller-supplied buffer in place — this is by
 * design (Requirement 6.4) and is what gives property-15 something
 * concrete to observe. Callers that must preserve their `r_bytes`
 * across the call (only the `__forTesting__` hook fits this profile;
 * the production path's `r_bytes` is a fresh CSPRNG draw with no
 * other observers) are responsible for passing in a copy.
 */
function computeProofCore(
  r_bytes: Uint8Array,
  r: bigint,
  x: bigint,
  publicKey_bytes: Uint8Array,
  challenge: Uint8Array,
): Uint8Array {
  // Commitment (Requirement 3.3). `BASE.multiply(r)` is the
  // constant-time ladder; `multiplyUnsafe` is forbidden here because
  // `r` is a secret nonce whose timing exposure would degrade
  // soundness toward the classical `s1 - s2 = (c1 - c2) · x` recovery
  // attack documented in `unit-nonce-reuse-attack.test.ts`.
  const R = BASE.multiply(r);
  const R_bytes = pointToBytes(R);

  // Fiat-Shamir scalar (Requirement 3.3, 8.1, 8.2). The transcript is
  // pinned in `transcript.ts`'s single function: this is the ONLY way
  // either prover or verifier can produce `c`, so prover/verifier
  // construction can never drift. `password` is structurally absent
  // from `computeFiatShamirScalar`'s signature.
  const c = computeFiatShamirScalar(R_bytes, publicKey_bytes, challenge);

  // Response (Requirement 3.4). `reduceScalar` returns the canonical
  // representative in `[0, L)`, so `s_bytes` is well-formed
  // (Requirement 4.8 admits `s = 0` as in-range but cryptographically
  // degenerate — it is on the verifier to decide correctness via the
  // verification equation, not on us to reject the encoding).
  const s = reduceScalar(r + c * x);
  const s_bytes = scalarToBytesLE(s);

  // Zero-fill the nonce buffer (Requirement 6.4, best-effort). See
  // file-header SECURITY-CRITICAL CONTRACT 3 for what this does and
  // does NOT prove. The bigint `r` and `x` cannot be wiped from JS;
  // we accept that residual exposure and document it in `SELF_REVIEW.md`
  // (Requirement 10.2).
  r_bytes.fill(0);

  // Output assembly (Requirement 3.1). `concatBytes` is re-exported
  // from `encoding.ts` so this module does not need a direct
  // `@noble/curves/utils.js` import — the audit guard in task 13.1
  // requires that the noble import surface be confined to
  // `encoding.ts` and `transcript.ts`.
  return concatBytes(R_bytes, s_bytes);
}

/**
 * Computes a 64-byte Schnorr proof of knowledge of `privateKey` over
 * a verifier-chosen `challenge`, with `password` carried as opaque
 * (and currently unused) metadata for forward-compatibility.
 *
 * The returned proof is `R_bytes || s_bytes` (32 bytes each), where
 * `R = r · G` is the commitment to a fresh CSPRNG-drawn nonce
 * `r ∈ [1, L)`, and `s = (r + c · x) mod L` is the response, with
 * `c = int_LE(SHA-512(R || X || challenge)) mod L` and
 * `x = int_LE(privateKey)` (Requirement 11.1: `x` is derived from
 * `privateKey` only; `password` does NOT participate).
 *
 * The proof verifies under `verify-proof.ts`'s
 * `s · G == R + c · publicKey` equation when invoked with the
 * matching `publicKey = x · G` (Property 6 round-trip).
 *
 * `password` is validated for shape (Requirement 3.7) but is then
 * treated as opaque bytes — it is NOT mixed into the scalar `x`, NOT
 * folded into the Fiat-Shamir transcript, and NOT touched in any
 * computation past validation (Requirements 3.3, 11.1; Property 10).
 *
 * Failure modes:
 *
 * - `InvalidInputError` with `code === 'INVALID_PRIVATE_KEY'` —
 *   `privateKey` is not a `Uint8Array(32)`, OR its little-endian
 *   decoding is `0`, OR its little-endian decoding is `≥ L`
 *   (Requirements 3.5, 11.4). The `≥ L` and `=== 0` checks are
 *   performed on the RAW decoding, not on `reduceScalar`'s output:
 *   `generateKeyPair` always produces in-range keys, so any
 *   out-of-range input is an integration error and we surface it
 *   verbatim rather than silently reduce.
 * - `InvalidInputError` with `code === 'INVALID_PASSWORD'` —
 *   `password` is not a `Uint8Array`, or its length exceeds 4096
 *   bytes (Requirement 3.7). The bound is wide enough to admit any
 *   reasonable user-supplied password yet rejects payloads large
 *   enough to suggest accidental data-passing or a DoS attempt.
 * - `InvalidInputError` with `code === 'INVALID_CHALLENGE'` —
 *   `challenge` is not a `Uint8Array(32)` (Requirement 3.6).
 * - `RandomnessError` with `code === 'RNG_FAILURE'` — the underlying
 *   `randomBytes32()` threw or short-read, OR rejection sampling
 *   exhausted its 256-iteration bound (Requirement 3.10). No
 *   partial or zero-padded proof is emitted on this failure path.
 *
 * @param privateKey 32-byte little-endian encoding of a scalar in
 *   `[1, L)`. Never read after `x` is derived; the buffer is not
 *   wiped by this function (the caller owns its lifecycle).
 * @param password   Opaque bytes, length `[0, 4096]`. Validated for
 *   shape and then ignored.
 * @param challenge  32-byte verifier-chosen challenge, ideally
 *   produced by `generateChallenge`.
 * @returns A fresh 64-byte `Uint8Array` carrying `R_bytes || s_bytes`.
 * @throws InvalidInputError When any input fails shape or range
 *   validation.
 * @throws RandomnessError When the CSPRNG throws, returns a short
 *   read, or rejection sampling exhausts its iteration bound.
 */
export function computeProof(
  privateKey: Uint8Array,
  password: Uint8Array,
  challenge: Uint8Array,
): Uint8Array {
  // Step 1 — input validation (Requirements 3.5, 3.6, 3.7).
  // `assertUint8ArrayLength` first checks the `Uint8Array` shape and
  // then the exact length, throwing `InvalidInputError` with the
  // supplied error code on either failure. The `password` validation
  // is split into a shape assertion and a length-range assertion so
  // that both bounds (`0 ≤ length ≤ 4096`) are enforced atomically
  // with a single `INVALID_PASSWORD` code.
  assertUint8ArrayLength(privateKey, 32, 'INVALID_PRIVATE_KEY', 'privateKey');
  assertUint8Array(password, 'INVALID_PASSWORD', 'password');
  assertUint8ArrayLengthBetween(password, 0, 4096, 'INVALID_PASSWORD', 'password');
  assertUint8ArrayLength(challenge, 32, 'INVALID_CHALLENGE', 'challenge');

  // Step 2 — scalar derivation (Requirements 3.5, 11.1, 11.4).
  // Decode `privateKey` as a little-endian bigint with NO reduction.
  // Reject the all-zero key (Requirement 11.4: `x = 0` would make the
  // proof trivially `R = r·G`, `s = r` and leak the nonce as `s`),
  // and reject any value `≥ L` (Requirement 3.5: a key outside
  // `[1, L)` is an integration error against `generateKeyPair`'s
  // contract that all produced keys are in-range). Any value in
  // `[1, L)` is already its own `reduceScalar` representative, so
  // assigning `x = n_raw` is exact — no information is lost by
  // skipping the explicit `reduceScalar` call.
  const n_raw = scalarFromBytesLE(privateKey);
  if (n_raw === 0n || n_raw >= L) {
    throw new InvalidInputError(
      'INVALID_PRIVATE_KEY',
      'privateKey decodes to a scalar outside [1, L)',
    );
  }
  const x = n_raw;

  // Step 3 — public key for transcript (Requirements 3.3, 11.2).
  // Constant-time scalar multiply — `multiplyUnsafe` is forbidden
  // here because `x` is the secret. `pointToBytes` produces the
  // canonical 32-byte Ed25519 encoding (RFC 8032 §5.1.2) used as the
  // middle segment of the Fiat-Shamir transcript.
  const publicKey_bytes = pointToBytes(BASE.multiply(x));

  // Step 4 — bounded rejection sampling for the nonce `r`
  // (Requirements 3.2, 6.1, 6.2, 6.3, 3.10).
  //
  // Each iteration draws a fresh 32-byte CSPRNG buffer, decodes it as
  // a little-endian bigint, reduces `mod L`, and accepts the draw iff
  // the reduced scalar is non-zero. On acceptance we hand the buffer
  // and bigint pair to the shared core helper, which builds the
  // proof, wipes the buffer, and returns. On `r === 0n` we redraw —
  // the rejected `r_bytes` is left to the GC without an explicit
  // wipe, matching the same hygiene policy `keypair.ts` documents:
  // a rejected candidate was never used to construct any secret-bearing
  // material, so its residual presence in memory carries no proof
  // material to leak.
  for (let i = 0; i < MAX_REJECTION_ITERATIONS; i += 1) {
    let r_bytes: Uint8Array;
    try {
      r_bytes = randomBytes32();
    } catch (e) {
      // In production, `rng.ts` already wraps every CSPRNG fault into
      // `RandomnessError` with stable code `'RNG_FAILURE'`, so this
      // re-wrap is a defense-in-depth no-op. Tests mock `rng.ts`
      // directly via `vi.mock` and may inject a raw `Error`
      // (property-13's `computeProof` portion does exactly this);
      // the re-wrap ensures the public-API contract "throw only
      // `InvalidInputError` and `RandomnessError`" holds at this
      // module's boundary regardless. We avoid double-wrapping by
      // letting an already-`RandomnessError` propagate unchanged so
      // the original `.cause` chain stays intact.
      if (e instanceof RandomnessError) throw e;
      throw new RandomnessError('CSPRNG failure', { cause: e });
    }

    // `reduceScalar(scalarFromBytesLE(r_bytes))` is the canonical
    // nonce derivation per design step 4. We reject `r === 0n` and
    // redraw — the only way `r === 0n` arises under a healthy CSPRNG
    // is when `r_bytes` decodes to a multiple of `L` inside
    // `[0, 2^256)`, which has probability `≈ 2^-252`. The bigint
    // comparison `r !== 0n` is on a `bigint` value, NOT on a byte
    // array, so it is permitted under Requirement 3.8.
    const r = reduceScalar(scalarFromBytesLE(r_bytes));
    if (r !== 0n) {
      return computeProofCore(r_bytes, r, x, publicKey_bytes, challenge);
    }
    // r === 0n: continue the loop and draw a fresh candidate. We do
    // not zero-fill the rejected `r_bytes` here for the same reason
    // `keypair.ts` does not zero-fill rejected candidates — rejected
    // bytes were never accepted as nonce material and the CSPRNG-state
    // information they carry is no more sensitive than any other
    // discarded RNG output.
  }

  // Loop exhausted without acceptance. Treated as an RNG anomaly per
  // design "Key design decisions → 2"; surfaces with the same stable
  // `.code` (`'RNG_FAILURE'`) as a CSPRNG throw or short read, so
  // callers can pattern-match on a single error code for all
  // randomness-related failures (Requirement 3.10).
  throw new RandomnessError('rejection sampling exhausted');
}

// __forTesting__ — DO NOT IMPORT FROM PRODUCTION CODE
/**
 * Test-only escape hatch that bypasses the live CSPRNG.
 *
 * `computeProofWithFixedNonce` performs the same input validation as
 * `computeProof`, derives `x` and `publicKey_bytes` identically, and
 * then routes through the SAME shared `computeProofCore` helper —
 * but with a caller-supplied `r_bytes` instead of a fresh CSPRNG
 * draw. This is the seam Property 10
 * (test/property-10-password-no-op.test.ts) and the adversarial
 * documentation test `unit-nonce-reuse-attack.test.ts` (task 7.7)
 * rely on: pinning the nonce removes CSPRNG variability so the only
 * remaining variable across two calls is whatever input the property
 * is varying.
 *
 * This export is NOT part of `@zkp-auth/core`'s public API surface
 * and `index.ts` does NOT re-export it. The audit-marker single-line
 * comment immediately above this declaration is grep-asserted by the
 * audit script in task 13.1 to appear EXACTLY ONCE in `src/`, locking
 * the contract that no production module pulls in this hook.
 *
 * Hook contract (per design.md ~line 1085 and tasks.md task 7.6):
 * the test MUST supply a well-formed `r_bytes` of exactly 32 bytes
 * whose `mod L` reduction is non-zero. The hook validates both
 * conditions and throws `InvalidInputError('INVALID_PROOF', ...)` on
 * violation — the `'INVALID_PROOF'` code is the closest fit in the
 * `ErrorCode` taxonomy (`r_bytes` is a piece of proof material) and
 * the misuse is a test-author bug rather than an end-user input
 * error, so the specific code does not need to land in the public
 * stable-code surface.
 *
 * `r_bytes` is COPIED before being passed to `computeProofCore`. The
 * core helper zero-fills its `r_bytes` argument as part of the
 * production wipe path; if it wiped the test caller's buffer, a
 * single test invocation that calls the hook twice with the same
 * `r_bytes` (e.g. property-10's `(p1, p2)` pair) would observe the
 * second call's `r` reduce to `0n` and throw. The defensive copy
 * preserves the shared-code-path design — the helper still does the
 * real wipe — while leaving the test caller's buffer intact for
 * re-use across the property body.
 */
export const __forTesting__ = {
  computeProofWithFixedNonce(
    privateKey: Uint8Array,
    password: Uint8Array,
    challenge: Uint8Array,
    r_bytes: Uint8Array,
  ): Uint8Array {
    // Same input validation as `computeProof` — Requirements 3.5,
    // 3.6, 3.7 — reused verbatim so the hook cannot accidentally
    // accept malformed inputs the production path would reject.
    assertUint8ArrayLength(privateKey, 32, 'INVALID_PRIVATE_KEY', 'privateKey');
    assertUint8Array(password, 'INVALID_PASSWORD', 'password');
    assertUint8ArrayLengthBetween(password, 0, 4096, 'INVALID_PASSWORD', 'password');
    assertUint8ArrayLength(challenge, 32, 'INVALID_CHALLENGE', 'challenge');

    // `r_bytes` shape check. The test contract requires a 32-byte
    // buffer; using `INVALID_PROOF` as the error code reflects that
    // `r_bytes` is proof-material-adjacent (it is the nonce buffer
    // from which `R` is derived) and that this surface is not part
    // of the public API.
    assertUint8ArrayLength(r_bytes, 32, 'INVALID_PROOF', 'r_bytes');

    // Same scalar derivation as `computeProof`. See the production
    // path's step-2 comment for the rationale of rejecting
    // `n_raw === 0n` and `n_raw >= L` on the raw decoding.
    const n_raw = scalarFromBytesLE(privateKey);
    if (n_raw === 0n || n_raw >= L) {
      throw new InvalidInputError(
        'INVALID_PRIVATE_KEY',
        'privateKey decodes to a scalar outside [1, L)',
      );
    }
    const x = n_raw;

    // Same publicKey derivation. Constant-time `BASE.multiply(x)`,
    // `multiplyUnsafe` forbidden.
    const publicKey_bytes = pointToBytes(BASE.multiply(x));

    // Caller-supplied nonce, mirroring the production reduction. We
    // reject `r === 0n` rather than redrawing — there is no live RNG
    // to redraw from in this code path, and the test's contract is
    // to supply a valid `r_bytes` in the first place.
    const r = reduceScalar(scalarFromBytesLE(r_bytes));
    if (r === 0n) {
      throw new InvalidInputError(
        'INVALID_PROOF',
        'r_bytes reduces to zero modulo L',
      );
    }

    // Defensive copy — see the JSDoc above for why this is necessary
    // for property-10's two-call pattern. `Uint8Array.from` allocates
    // a fresh backing buffer that the core helper will zero-fill in
    // place; the original `r_bytes` the caller supplied remains
    // untouched.
    const r_bytes_owned = Uint8Array.from(r_bytes);

    return computeProofCore(r_bytes_owned, r, x, publicKey_bytes, challenge);
  },
} as const;
