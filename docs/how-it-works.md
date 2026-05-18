# How It Works

ZKP Auth uses a **Schnorr Proof of Knowledge** — a cryptographic technique that lets you prove you know a secret without revealing it. Here's what that means in plain terms, and how the full login flow works.

## The Schnorr proof, explained simply

Think of it like this:

> Alice wants to prove she knows the combination to a safe — without opening it in front of you. She does this by solving a puzzle you give her that *only* someone with the combination could solve. You never see the combination; you only see her solution.

More concretely, ZKP Auth works on **elliptic curve math**. If `G` is a publicly known point on the Ed25519 curve:

- Alice's **private key** is a secret number `x`.
- Alice's **public key** is the point `X = x · G` — published to the server at registration.

The server knows `X`. It **cannot** recover `x` from `X` — that's the [discrete logarithm problem](https://en.wikipedia.org/wiki/Discrete_logarithm), which is computationally infeasible on Ed25519.

### The three-move Schnorr protocol

A single authentication exchange involves three values:

| Symbol | Name | Who produces it | What it is |
|--------|------|-----------------|------------|
| `R` | Commitment | Browser | A random point `r · G`; `r` is a fresh nonce |
| `c` | Challenge | Both (deterministically) | `SHA-512(R ∥ X ∥ challenge) mod L` |
| `s` | Response | Browser | `(r + c · x) mod L` |

The browser sends `(R, s)` as the 64-byte proof. The server checks:

```
s · G  ==  R + c · X
```

**Why does this work?** Substitute the definitions:

```
s · G = (r + c·x) · G
      = r·G + c·(x·G)
      = R   + c·X      ✓
```

The server verifies the equation holds **without ever learning `x` or `r`**.

### The Fiat-Shamir transform

In the interactive protocol, the server sends `c` after receiving `R`. This library uses the **Fiat-Shamir transform** to make it non-interactive: `c` is computed as a hash of `R`, the public key `X`, and the server-issued challenge nonce. This means:

- The proof is computed entirely in the browser in one shot.
- The hash pins the proof to this specific public key and this specific session nonce — it cannot be replayed.

::: info Hash construction
`c = int_LE(SHA-512(R_bytes ∥ publicKey_bytes ∥ challenge_bytes)) mod L`

This exact construction is pinned in a single function (`computeFiatShamirScalar`) shared by both the prover and verifier, so they can never drift.
:::

## Why the password never leaves the browser

The password is used **only** to derive a deterministic keypair in the browser, via PBKDF2:

```
privateKey = PBKDF2-SHA512(password, salt=username, iterations=100_000) → scalar in [1, L)
publicKey  = privateKey · G   (Ed25519 base point multiply)
```

After derivation:

1. `publicKey` (32 bytes) is sent to the server **once** at registration.
2. `privateKey` is kept in the browser's JavaScript heap for the session.
3. The **password itself** is never sent anywhere — not even as a hash.

On subsequent logins the browser re-derives the same `privateKey` from the same credentials. The server verifies the proof against the stored `publicKey`. No password comparison ever happens on the server.

::: warning What this is NOT
The server does not verify passwords. It verifies **proofs**. If you lose access to your username and password, there is no password reset flow built into this library — you would need to implement one at the application level (e.g. email-based re-registration).
:::

## Full authentication flow

### Registration

```
Browser                                          Server
  │                                                │
  │  1. username + password entered                │
  │                                                │
  │  2. PBKDF2(password, salt=username)            │
  │     → privateKey (stays in memory)             │
  │     → publicKey  = privateKey · G              │
  │                                                │
  │──── POST /auth/register ──────────────────────▶│
  │     { userId, publicKeyHex }                   │
  │                                                │  3. store(userId → publicKey)
  │◀─── 200 OK ────────────────────────────────────│
  │                                                │
```

### Login

```
Browser                                          Server
  │                                                │
  │  1. username + password entered                │
  │                                                │
  │  2. PBKDF2(password, salt=username)            │
  │     → privateKey (re-derived or from memory)   │
  │                                                │
  │──── POST /auth/challenge ─────────────────────▶│
  │     { userId }                                 │
  │                                                │  3. challenge = CSPRNG(32 bytes)
  │                                                │     store(userId → challenge, TTL=60s)
  │◀─── { challengeHex } ──────────────────────────│
  │                                                │
  │  4. r = CSPRNG() — fresh nonce                 │
  │     R = r · G                                  │
  │     c = SHA-512(R ∥ X ∥ challenge) mod L       │
  │     s = (r + c · privateKey) mod L             │
  │     proof = R_bytes ∥ s_bytes  (64 bytes)      │
  │                                                │
  │──── POST /auth/verify ────────────────────────▶│
  │     { userId, proofHex }                       │
  │                                                │  5. challenge = consume(userId)  ← one-time
  │                                                │     X = lookup(userId)
  │                                                │     c = SHA-512(R ∥ X ∥ challenge) mod L
  │                                                │     verify: s·G == R + c·X
  │                                                │     issue JWT
  │◀─── Set-Cookie: auth=<JWT> ────────────────────│
  │                                                │
```

### Replay prevention

Step 5 is critical: `consume(userId)` **atomically deletes** the challenge from the store after reading it. A replayed `proof` arrives with no matching challenge → verification fails immediately. Each 32-byte challenge is single-use by design.

The challenge also has a configurable TTL (default 60 seconds). An expired challenge returns `null` from the store before the proof is even checked.

## Security properties

| Property | How it's enforced |
|---|---|
| Password never transmitted | PBKDF2 derivation is client-side only |
| Proofs are non-replayable | Server challenge is consumed on first use |
| Proofs are session-bound | Fiat-Shamir hashes the challenge into `c` |
| No timing oracle on verify | Final point comparison uses `crypto.timingSafeEqual` |
| Malformed proofs → `false`, not exception | Protects against oracle distinguishing malformed vs. wrong |
| Private key derivation is uniform | Rejection sampling — never `mod L` reduction |

For a deeper dive, see the [Security Model](/security) page.
