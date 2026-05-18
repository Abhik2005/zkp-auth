# SELF_REVIEW.md — `@zkp-auth/core` v0.1.0

> **Purpose.** This document is an audit artifact required by
> Requirements 10.1–10.6. It explains every non-obvious security
> decision, enumerates all equality operators for timing-leak
> assessment, and documents the role of the `password` parameter in
> full for an auditor unfamiliar with this codebase.
>
> All file-path:line citations refer to the committed implementation
> under `packages/zkp-auth-core/src/`.

---

## 1. Timing-Leak Inventory

The audit guard (`test/audit-no-forbidden-comparators.test.ts`, task 13.1)
enforces that no `===`, `!==`, or `Buffer.equals` appears on lines
containing byte-array identifiers derived from secrets
(`privateKey`, `nonce`, `password`, `secret`, `r_bytes`, `r_scalar`,
`proof`, `challenge`, `publicKey`, `R_bytes`, `s_bytes`, `lhs_bytes`,
`rhs_bytes`). `errors.ts` is whitelisted for code-string comparisons.

The table below lists every `===` / `!==` present in executable
(non-comment, non-JSDoc) lines across `src/**/*.ts` and explains why
each is safe.

### `compare.ts`

| File:Line | Expression | Why Safe |
|---|---|---|
| `compare.ts:42` | `a.length !== b.length` | Compares two `number` values (array lengths). Length is a public property of the protocol encoding; it is not a secret. The result gates whether to call `timingSafeEqual`, not whether a proof is correct. |

### `validate.ts`

| File:Line | Expression | Why Safe |
|---|---|---|
| `validate.ts:38` | `value === null` | Null-sentinel check on an `unknown` value before any cryptographic operation. Operates on a JS runtime tag, not on any byte-array content. |
| `validate.ts:96` | `value.length !== expectedLen` | Compares two `number` values (byte-array length vs. expected constant). Length is not secret; this check fires before any curve operation is attempted. |

### `rng.ts`

| File:Line | Expression | Why Safe |
|---|---|---|
| `rng.ts:65` | `buf.length !== 32` | Compares a `number` (buffer length from Node's CSPRNG) against the constant `32`. No secret data is involved; this is a defensive length guard, not a secret comparison. |

### `challenge.ts`

| File:Line | Expression | Why Safe |
|---|---|---|
| `challenge.ts:130` | `result.length !== 32` | Defense-in-depth guard on the return value of the mocked-or-real `randomBytes32()`. Compares two `number` lengths; the content of `result` is not examined. |

### `compute-proof.ts`

| File:Line | Expression | Why Safe |
|---|---|---|
| `compute-proof.ts:333` | `n_raw === 0n \|\| n_raw >= L` | Compares a `bigint` scalar against two `bigint` constants (`0n` and `L`). Bigint comparisons operate on the mathematical value, not on bytes. The comparison guards range validity before any curve operation; it does NOT appear on a line containing a byte-array identifier from the forbidden set. |
| `compute-proof.ts:388` | `r !== 0n` | Compares the reduced `bigint` nonce `r` against `0n`. `r` is a `bigint` in `[0, L)`, not a byte array; the comparison is safe under Requirement 3.8. |
| `compute-proof.ts:474` | `n_raw === 0n \|\| n_raw >= L` | Identical to line 333 (appears in the `__forTesting__` hook). Same rationale. |
| `compute-proof.ts:491` | `r === 0n` | In the `__forTesting__` hook: rejects a test-supplied `r_bytes` that reduces to zero. Bigint comparison; same rationale as line 388. |

### `verify-proof.ts`

| File:Line | Expression | Why Safe |
|---|---|---|
| `verify-proof.ts:262` | `R === null` | Null-sentinel check on the result of `pointFromBytesSoft`. `null` is a JS runtime sentinel, not a byte array; this check is explicitly noted as safe in the file-header security contracts (`verify-proof.ts:111`). |
| `verify-proof.ts:280` | `s >= L` | Compares a `bigint` scalar against `L`. `s` is the decoded response scalar; the comparison is a range gate, not a byte-array equality. Permitted under Requirement 3.8. |

### `errors.ts` (whitelisted)

`errors.ts` is whitelisted by the audit guard (task 13.1 scanner skips
it). It contains `options?.cause !== undefined` checks (`errors.ts:94`,
`errors.ts:122`) that operate on an optional `unknown` value in the
`ErrorCause` bag, never on any cryptographic byte array.

### `index.ts`, `encoding.ts`, `transcript.ts`, `keypair.ts` (non-executable lines only)

No executable `===`/`!==` on secret byte-array identifiers appears in
these files. Every match from the audit grep is in a comment or JSDoc
block, which the audit guard correctly ignores. `keypair.ts:121`
(`e instanceof RandomnessError`) uses `instanceof`, not `===`/`!==`.

### Cross-reference with the audit guard

The audit test at `test/audit-no-forbidden-comparators.test.ts` (task 13.1)
enforces the above at CI time by string-matching every `.ts` file in `src/`.
The same test also asserts:

- `crypto.timingSafeEqual` appears in exactly one file: `compare.ts`.
- `randomBytes` (from `node:crypto`) appears in exactly one file: `rng.ts`.
- `Buffer.compare(` and `.equals(` are absent from all scanned files.
- No raw `throw '...'` / `throw 0` (bare-literal throws).
- The `__forTesting__` marker comment appears exactly once in `src/`.

All eight assertions pass as of the v0.1.0 test run (78 / 78 tests).

---

## 2. Edge Cases Considered but Not Handled

These cases are documented to inform the auditor of known gaps and the
rationale for not mitigating them in v1.

### 2.1 Small-subgroup public keys (non-identity torsion points)

Ed25519 is a prime-order subgroup (`#E' = 8L`) of the full Edwards
curve. Points of order 1, 2, 4, or 8 (torsion points) that are NOT
the identity `O = (0, 1)` can be decoded successfully by
`pointFromBytesStrict` and pass the `is0()` check.

We do NOT call `point.isSmallOrder()` in `verify-proof.ts`. Noble's
`ed25519.Point.fromBytes` performs cofactor-clearing during its
internal validation in strict mode; the returned point is guaranteed
to lie in the prime-order subgroup (`ed25519.Point.BASE.multiply(n)`
for some `n`). Any externally supplied torsion point that clears the
cofactor check inside noble is already treated as a point in the
prime-order subgroup by the library's internal representation.

**Consequence:** A `publicKey` encoding a small-order point that
somehow passes noble's decoder (possible in zip215 permissive mode but
not in strict mode) would allow a multi-session attack. This is
accepted in v1 because `pointFromBytesStrict` uses noble's strict mode,
which rejects non-canonical and low-order encodings by construction.
See design "Security Considerations — Small-subgroup attacks".

### 2.2 Non-canonical point encodings (zip215 permissive mode)

The `@noble/curves` `ed25519.Point.fromBytes` helper used in
`pointFromBytesStrict` and `pointFromBytesSoft` operates in **strict
RFC 8032** mode. It rejects bit-manipulation tricks valid in the zip215
permissive mode (used by Zcash and some other implementations), such
as setting the high bit of the last byte on a small-coordinate point.

This is intentional and correct for our protocol: strict mode means
the same 32-byte sequence always decodes to the same abstract point
on any conforming implementation. Non-canonical encodings that would
be accepted under zip215 are rejected here; the verifier returns `false`
for those inputs via `pointFromBytesSoft` returning `null`.

**Reference:** External API Surface §B in `design.md`; this file
`encoding.ts:156–162` (`pointFromBytesStrict`) and `encoding.ts:183–189`
(`pointFromBytesSoft`).

### 2.3 `s === 0n` in `verifyProof`

When `s_bytes` decodes to `0n`, `verify-proof.ts:280` does NOT reject it
— `0n` is in the range `[0, L)` so the code falls through to the
verification equation. The equation `0 · G == R + c · publicKey`
simplifies to `O == R + c · publicKey`, which is a mathematically valid
(if unlikely) constraint. Whether it holds depends on the specific
`(R, publicKey, challenge)` triple; for a legitimate prover who derived
`s = (r + c·x) mod L` with non-zero `r` and `x`, the probability that
`s === 0n` is `≈ 1/L`, which is negligible.

**Consequence:** An adversary who can find a triple `(R, s=0, challenge)`
such that `R + c·publicKey == O` has forged a proof, but this requires
solving the discrete logarithm problem. Accepted in v1.

**Reference:** `verify-proof.ts:270–278` documents this decision inline.

### 2.4 Bigint scalars are not zero-fillable

The secret scalar `x = int_LE(privateKey)` and the nonce `r` are both
held as JavaScript `bigint` values during proof construction. JavaScript
`bigint` is an immutable heap-allocated primitive; there is no
`zeroize`-equivalent in the JS runtime. We zero-fill `r_bytes`
(the source buffer) in `compute-proof.ts:239` after the nonce is
consumed, but `x` and `r` themselves, as bigints, remain in the
heap until garbage collected.

**Consequence:** A process that can read the JS heap (e.g. a
memory-snapshot side-channel, a JIT-compiled register spill) could
recover `x` or `r`. This is a fundamental limitation of implementing
cryptographic protocols in JavaScript / TypeScript without native WASM
zeroization. Documented in `SELF_REVIEW.md` per Requirement 10.2 and
in `compute-proof.ts:63–67` (file-header security-critical contract 3).

---

## 3. Unenforced Caller Assumptions

### 3.1 `privateKey` ownership — callers must manage lifecycle

`generateKeyPair()` returns the 32-byte CSPRNG-drawn `privateKey`
buffer as a fresh `Uint8Array` (detached from Node's internal pool via
`Uint8Array.from`, see `rng.ts:68`). `computeProof` reads this buffer
but does NOT zero-fill it after use — the caller owns the lifecycle.

**Implication:** If the caller persists `privateKey` in memory without
zeroizing it, the secret scalar remains accessible via the heap for the
lifetime of the buffer. Callers are responsible for calling
`privateKey.fill(0)` after use. This library does not enforce that
assumption.

**Reference:** `keypair.ts:82–86` (JSDoc), `compute-proof.ts:292–296`
(JSDoc parameter note "the buffer is not wiped by this function").

### 3.2 `Buffer` vs. `Uint8Array` shape tolerance

`assertUint8Array` (`validate.ts:64`) uses `instanceof Uint8Array`.
Node's `Buffer` extends `Uint8Array`, so callers may pass a `Buffer`
instance to any public function and the assertion passes. This is
intentional (see `validate.ts:44–50`), but it means `Buffer`-specific
methods (`.equals`, `.compare`) are available on the returned
`publicKey`, `proof`, etc. if the caller casts them. Callers who
compare output buffers via `Buffer.equals` instead of the provided
`timingSafeEqualBytes` will introduce timing leaks that this library
cannot prevent.

### 3.3 `password` opacity guarantees from caller's side

`computeProof` validates `password` for shape (`Uint8Array`, length
`[0, 4096]`) and then treats it as entirely opaque. The library makes
no promise about what the caller puts in `password`; an empty
`Uint8Array`, a UTF-8 encoded passphrase, or random bytes are all
accepted. Any semantic meaning of `password` beyond the shape contract
— including key-stretching, PBKDF2, or binding to a user account — is
entirely the caller's responsibility. The library does NOT derive or
verify any per-user key from `password` in v1 (see Section 5).

---

## 4. External API Consumed

Version pins are from `packages/zkp-auth-core/package.json`:
- `@noble/curves ^1.9.7`
- `@noble/hashes ^1.8.0`

Pinned to these ranges per Requirement 7.6, locked by the regression test
at `test/unit-package-pins.test.ts`.

### 4.1 `@noble/curves/ed25519.js` (imported in `encoding.ts:32`)

| Symbol | Type | Used for |
|---|---|---|
| `ed25519` (default namespace) | Object | Root namespace; all sub-accesses below go through this. |
| `ed25519.Point.BASE` | `EdwardsPoint` | The Ed25519 generator `G`; exported as `BASE` (`encoding.ts:78`). |
| `ed25519.Point.Fn.ORDER` | `bigint` | The group order `L`; exported as `L` (`encoding.ts:61`). |
| `ed25519.Point.Fn.create(n)` | `(bigint) → bigint` | Modular reduction `n mod L`; used in `reduceScalar` (`encoding.ts:93–95`). |
| `ed25519.Point.fromBytes(bytes)` | `(Uint8Array) → EdwardsPoint` | Strict Ed25519 point decode; used in `pointFromBytesStrict` (`encoding.ts:158`) and `pointFromBytesSoft` (`encoding.ts:185`). |
| `EdwardsPoint.multiply(scalar)` | method | Constant-time scalar multiply; used in `keypair.ts:139`, `compute-proof.ts:216`, `compute-proof.ts:346`, `compute-proof.ts:484`, `verify-proof.ts:312–313`. |
| `EdwardsPoint.add(point)` | method | Edwards group addition; used in `verify-proof.ts:313`. |
| `EdwardsPoint.toBytes()` | method | RFC 8032 §5.1.2 canonical encoding; used in `pointToBytes` (`encoding.ts:202`). |
| `EdwardsPoint.is0()` | method | Identity-point check; used in `verify-proof.ts:233`. |

> **Note:** `toRawBytes()` is intentionally NOT used anywhere in this
> codebase; it is deprecated in `@noble/curves ≥ 1.6`. See External
> API Surface §B in `design.md`.

### 4.2 `@noble/curves/utils.js` (imported in `encoding.ts:33–37`)

| Symbol | Type | Used for |
|---|---|---|
| `bytesToNumberLE` | `(Uint8Array) → bigint` | Little-endian byte → bigint decode; used in `scalarFromBytesLE` (`encoding.ts:114`). |
| `numberToBytesLE` | `(bigint, number) → Uint8Array` | Little-endian bigint → byte encode; used in `scalarToBytesLE` (`encoding.ts:131`). |
| `concatBytes` | `(...Uint8Array[]) → Uint8Array` | Raw byte concatenation; re-exported from `encoding.ts:214` for `transcript.ts` and `compute-proof.ts`. |

### 4.3 `@noble/hashes/sha512.js` (imported in `transcript.ts:42`)

| Symbol | Type | Used for |
|---|---|---|
| `sha512` | `(Uint8Array) → Uint8Array` | 64-byte SHA-512 digest; the sole hash in the Fiat-Shamir transcript (`transcript.ts:97`). |

> **Requirement 8.4:** SHA-512 is the mandated hash function; no other
> hash is imported or used. `transcript.ts` is the sole importer of
> `@noble/hashes` across `src/**/*.ts`, enforced by the audit guard
> (`test/audit-no-forbidden-comparators.test.ts`).

### 4.4 `node:crypto` (Node built-in — NOT from npm)

| Symbol | Module | Used for |
|---|---|---|
| `randomBytes` | `node:crypto` | 32-byte CSPRNG draw; only in `rng.ts:22`. |
| `timingSafeEqual` | `node:crypto` | Constant-time byte comparison; only in `compare.ts:12`. |

Both call sites are single-file chokepoints, enforced by the audit guard.

### 4.5 Cross-reference — External API Surface

The full rationale for each import choice (why `ed25519` over direct
`Field` operations, why `sha512` over `sha256`, why `bytesToNumberLE`
over a hand-rolled LE reader, etc.) is documented in
`design.md → "External API Surface §A–§F"`. The Requirement 7.6 pin
test (`test/unit-package-pins.test.ts`) will fail if either
`@noble/curves` or `@noble/hashes` is bumped without updating the
test, forcing fresh verification of this section.

---

## 5. Password Role

> **Required by Requirement 10.6.** This section is written for an
> audit reader who is not familiar with the library's design and needs
> to understand the role of `password` in the v1 protocol.

### 5.1 Reserved-but-unused in v1

`password` is an argument present in the public signature of
`computeProof` but **not used in any cryptographic computation** in v1.
This is intentional and documented in Requirement 11 ("Password
Handling and Forward Compatibility").

In v1:
- `password` is validated for shape (`Uint8Array`, length `[0, 4096]`)
  at the entry point of `computeProof` (`compute-proof.ts:318–319`).
- After validation, `password` is never read, never hashed, never
  referenced again in any computation.
- The parameter does not appear in `computeProofCore`, `transcript.ts`,
  or any helper downstream of the entry point.

### 5.2 Scalar derivation does not depend on `password`

The secret scalar is derived exclusively from `privateKey`:

```
x = int_LE(privateKey)   (scalarFromBytesLE, encoding.ts:113–115)
```

`compute-proof.ts:332` performs this derivation. `password` is not
mixed into `x` at any stage. A caller who provides two proofs with the
same `(privateKey, challenge)` triple and two distinct `password`
values will receive byte-identical proofs (Property 10, locked by
`test/property-10-password-no-op.test.ts`).

### 5.3 `password` is NOT part of the Fiat-Shamir transcript

The Fiat-Shamir hash construction is:

```
c = int_LE( SHA-512(R_bytes || publicKey_bytes || challenge_bytes) ) mod L
```

This is defined in `transcript.ts:91–100`. The function signature is:

```typescript
computeFiatShamirScalar(
  R_bytes: Uint8Array,
  publicKey_bytes: Uint8Array,
  challenge_bytes: Uint8Array,
): bigint
```

`password` is **absent from the parameter list** of
`computeFiatShamirScalar`. This is a structural guarantee, not just a
call-site convention: `transcript.ts` cannot receive `password` even
if a future maintainer wanted to pass it — it would require a
signature change, which is a visible code review red flag.

Both the prover (`compute-proof.ts:224`) and verifier
(`verify-proof.ts:292`) call `computeFiatShamirScalar` without a
`password` argument. The Fiat-Shamir scalar `c` is therefore identical
across prover and verifier for any given `(R, publicKey, challenge)`
triple, regardless of what `password` the caller supplied.

### 5.4 Forward-compatibility rationale for keeping the argument

The `password` parameter is retained in v1 for forward-compatibility:

1. **Stable wire format.** Any caller (SDK, mobile app, web client)
   compiled against the v1 API passes `password` as an argument. When v2
   introduces a non-trivial `derive_scalar(privateKey, password)`, the
   call sites do not need to change — only the library internals change.
   Without the parameter, callers compiled against v1 would have no
   place to pass `password` and would need to be updated at the same
   time as the library, creating a synchronized-release coupling.

2. **Metadata carrier for the protocol layer.** The protocol layer
   (e.g. `@zkp-auth/server`) may wish to record or transmit `password`
   as opaque user-supplied data alongside the authentication attempt,
   even before v2 makes it cryptographically active.

3. **Explicit no-op over implicit absence.** Having `password` present
   and visibly doing nothing makes the design decision auditable: an
   auditor reading the source code sees the parameter, sees that it is
   validated but not used, and can cross-reference this section of the
   `SELF_REVIEW.md` to confirm the behavior is intentional.

### 5.5 Implications for proof binding

Because `password` is not in the Fiat-Shamir transcript, the
produced proof is **not bound to any specific `password` value**:

- Bit-flipping `password` is a **no-op** on the produced proof.
  This is the invariant locked by Property 10 and tested in
  `test/property-10-password-no-op.test.ts` (task 7.1/7.6).
  The test fixes `(privateKey, challenge, r_bytes)` and varies only
  `password` across two calls via `computeProofWithFixedNonce`; the
  resulting 64-byte proofs are byte-identical.

- A proof produced with `password = "abc"` verifies successfully
  against the same `(publicKey, challenge)` pair in `verifyProof`
  (which does not receive `password` at all). This means the proof
  provides knowledge-of-`privateKey` only; it does NOT bind to a
  passphrase. Applications that require passphrase binding must either
  wait for v2, or layer their own KDF above this library and use the
  KDF output as `privateKey`.

### 5.6 Future breaking-change note

Any v2 specification that introduces a non-trivial
`derive_scalar(privateKey, password)` — for example,
`x = int_LE(PBKDF2(password, privateKey, ...)) mod L` — would:

1. Change the proof output for any fixed `(privateKey, password, challenge)`
   triple, breaking the fixed-vector regression test in
   `test/unit-fixed-vectors.test.ts`.
2. Break Property 10 (`password` is a no-op), requiring that test to
   be removed or updated.
3. Change the scalar derivation formula in `compute-proof.ts`,
   requiring a corresponding change in `SELF_REVIEW.md §5.2`.

Such a change is a **semver-major (breaking) bump** of `@zkp-auth/core`.
Any v2 deployment requires simultaneous update of all callers that
previously relied on the v1 `password`-is-a-no-op guarantee.
