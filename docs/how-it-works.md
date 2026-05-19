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

---

## Why no password is involved in the cryptographic proof

ZKP Auth v0.2+ is fully **passwordless** at the protocol level. There is no password-derived key and no password-oracle vulnerability.

### Key generation (registration)

```
privateKey = random Ed25519 scalar, uniform in [1, L)
publicKey  = privateKey · G   (Ed25519 base point multiply)
```

`privateKey` is generated once per device using **bounded rejection sampling** over `globalThis.crypto.getRandomValues`. The key has 252 bits of entropy — far more than any password.

### Local key encryption (device storage)

The private key is **never stored in plaintext**. Before being written to IndexedDB, it is wrapped:

```
salt         = CSPRNG(16 bytes)               — fresh per registration
wrappingKey  = Argon2id(PIN, salt,            — 64 MB memory, 3 passes, 1 lane
                 m=65536, t=3, p=1)
iv           = CSPRNG(12 bytes)               — fresh per registration
ciphertext   = AES-256-GCM(wrappingKey, privateKey, iv)

stored: { version, pubKeyHex, salt, iv, ciphertext }
```

**The PIN is the only secret the user ever types.** It never leaves the browser. A server DB breach reveals only public keys.

### Login

On login, the browser:
1. Retrieves the encrypted blob from IndexedDB
2. Re-derives `wrappingKey` from PIN + stored salt (Argon2id)
3. Decrypts the private key (AES-256-GCM — wrong PIN → tag mismatch → error)
4. Computes the Schnorr proof
5. **Zeroes the private key unconditionally in a `finally` block**

The PIN is discarded immediately after decryption.

---

## Full authentication flow

### Registration

```
Browser                                          Server
  │                                                │
  │  1. privateKey = CSPRNG scalar                 │
  │     publicKey  = privateKey · G                │
  │                                                │
  │  2. wrappingKey = Argon2id(PIN, salt)           │
  │     ciphertext  = AES-256-GCM(wk, privateKey)  │
  │     Store encrypted blob → IndexedDB           │
  │                                                │
  │──── POST /auth/register ──────────────────────▶│
  │     { userId, publicKeyHex }                   │
  │                                                │  3. store(userId → publicKey)
  │◀─── 201 Created ───────────────────────────────│
  │                                                │
```

### Login

```
Browser                                          Server
  │                                                │
  │  1. PIN entered                                │
  │                                                │
  │  2. Load blob from IndexedDB                   │
  │     wrappingKey = Argon2id(PIN, stored_salt)   │
  │     privateKey  = AES-256-GCM.decrypt(blob)    │
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
  │     privateKey.fill(0)  ← zeroed here          │
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

---

## Security properties

| Property | How it's enforced |
|---|---|
| No password involved | Keypair is randomly generated — no KDF from user secret |
| Private key never leaves device | Encrypted in IndexedDB; decrypted in memory only during proof computation |
| Private key zeroed after use | `finally` block calls `privateKey.fill(0)` unconditionally |
| Proofs are non-replayable | Server challenge is consumed on first use |
| Proofs are session-bound | Fiat-Shamir hashes the challenge into `c` |
| PIN brute-force is expensive | Argon2id: 64 MB memory wall per attempt |
| No timing oracle on verify | Final point comparison uses `crypto.timingSafeEqual` |
| Malformed proofs → `false`, not exception | Protects against oracle distinguishing malformed vs. wrong |
| Private key derivation is uniform | Rejection sampling — never `mod L` reduction |
| Public key oracle impossible | Public key is random — no relationship to any password |

For a deeper dive, see the [Security Model](/security) page.
