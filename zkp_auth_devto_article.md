---
title: I built truly passwordless ZKP auth — no password ever touches your server
published: false
tags: javascript, security, authentication, node
cover_image: https://raw.githubusercontent.com/Abhik2005/zkp-auth/refs/heads/main/cover.svg
---

Every time you hear about a major breach, the headline is the same: *"Millions of passwords exposed."* Attackers get in, dump the database, and walk away with your users' bcrypt hashes. Given enough time and a GPU farm, weak passwords crack. Even strong ones end up in breach databases. The root cause is always the same: **the password reached your server**. It lived in a request body, got hashed, got stored, and now it's someone else's problem.

What if there were no password at all?

---

## What is Zero-Knowledge Proof auth?

Zero-Knowledge Proofs sound academic, but the core idea is surprisingly simple: **you can prove you know a secret without revealing what the secret is**.

Here's a real-world analogy. Imagine you want to prove to a bouncer that you know the secret password to a club, but you don't want to say it out loud where others can hear. Instead, the bouncer gives you a random challenge token and asks you to sign it in a way that only someone who knows the password could. You hand back the signed token. The bouncer checks the signature. You're in — and you never said the password.

That's exactly what ZKP auth does at a cryptographic level. **But there's an even stronger version of this: no password is involved at all.** The browser generates a random Ed25519 keypair, encrypts the private key with a local PIN, and stores it in IndexedDB. On login, the PIN decrypts the key locally, the private key signs a server-issued challenge using a Schnorr proof, and then the key is zeroed from memory. The server stores only the 32-byte public key — mathematically useless without the private scalar, which only the device holds.

No password database means **no password database to breach**.

---

## The old approach vs. the new one

Many "ZKP auth" implementations still derive the keypair from a password via PBKDF2 or similar. This is better than sending the password plaintext, but it creates a **public-key oracle**: if an attacker steals the server database, they can check candidate passwords offline — `derivedKey(guess) == storedPublicKey?` — at the same speed as testing bcrypt hashes.

ZKP Auth v0.2 eliminates this entirely:

```
Old (v0.1):  privateKey = PBKDF2(password, username, 600_000 iters)
             → publicKey depends on password → oracle attack possible

New (v0.2):  privateKey = CSPRNG() — truly random
             → publicKey has zero relationship to any password
             → offline attack is impossible: there is nothing to guess against
```

The key is protected locally with **Argon2id** (64 MB memory cost) — GPU-parallel brute force on a stolen IndexedDB blob is expensive even for short PINs.

---

## How the library works

**ZKP Auth** is a TypeScript monorepo with four focused packages:

| Package | What it does |
|---|---|
| `@zkp-auth/core` | Schnorr proof primitives (Ed25519) |
| `@zkp-auth/server` | Express middleware — register, challenge, verify |
| `@zkp-auth/client` | Browser client — random keypair, Argon2id local storage, proof |
| `@zkp-auth/react` | `useZKPAuth()` hook for React apps |

### Install

```bash
# Server
npm install @zkp-auth/server

# Browser (vanilla)
npm install @zkp-auth/client

# Browser (React)
npm install @zkp-auth/client @zkp-auth/react
```

### Server — three middleware functions, that's it

```ts
// server.ts
import express from 'express';
import cookieParser from 'cookie-parser';
import {
  zkpRegister,
  zkpChallenge,
  zkpVerify,
  InMemoryChallengeStore,
} from '@zkp-auth/server';

const app = express();
app.use(express.json());
app.use(cookieParser());

// Swap InMemoryChallengeStore for Redis/Postgres in production
const store = new InMemoryChallengeStore();

// Your user store — replace with real DB calls
const users = new Map<string, Uint8Array>();

// Route 1 — register: receives and stores the user's public key
app.post(
  '/auth/register',
  zkpRegister({
    getPublicKey: async (userId) => users.get(userId) ?? null,
    savePublicKey: async (userId, publicKey) => {
      users.set(userId, publicKey);
    },
  }),
  (_req, res) => res.json({ ok: true }),
);

// Route 2 — challenge: issues a fresh one-time nonce
app.post(
  '/auth/challenge',
  zkpChallenge({ store }),
  (_req, res) => res.json({ challengeHex: res.locals.zkpChallengeHex }),
);

// Route 3 — verify: checks the proof and issues a JWT cookie
app.post(
  '/auth/verify',
  zkpVerify({
    getPublicKey: async (userId) => users.get(userId) ?? null,
    store,
    jwtSecret: process.env.JWT_SECRET!,
  }),
  (_req, res) => {
    res.cookie('auth', res.locals.zkpToken, {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
    });
    res.json({ ok: true });
  },
);
```

### Client — React hook

```tsx
// AuthForm.tsx
import { useZKPAuth } from '@zkp-auth/react';

export function AuthForm() {
  const { register, login, hasLocalKey, logout, isAuthenticated, loading, error, user } =
    useZKPAuth();

  if (isAuthenticated) {
    return (
      <div>
        <p>Welcome, {user?.userId}!</p>
        <button onClick={logout}>Log out</button>
      </div>
    );
  }

  return (
    <form onSubmit={async (e) => {
      e.preventDefault();
      const f = new FormData(e.currentTarget);
      const username = f.get('username') as string;
      const pin      = f.get('pin') as string;

      // Route to register or login automatically — no separate forms needed
      const exists = await hasLocalKey(username);
      exists ? await login(username, pin) : await register(username, pin);
    }}>
      {error && <p style={{ color: 'red' }}>{error.message}</p>}

      <input name="username" placeholder="Username" required />
      <input
        name="pin"
        type="password"
        placeholder="PIN (stays on this device — never sent)"
      />
      <button type="submit" disabled={loading}>
        {loading ? 'Authenticating…' : 'Continue'}
      </button>
    </form>
  );
}
```

That's the entire auth surface. No password ever touches the wire or the server.

---

## How it works under the hood

The protocol is a **Schnorr Proof of Knowledge** over **Ed25519** with the Fiat–Shamir transform. Here's the full flow:

```
BROWSER                                          SERVER
──────────────────────────────────────────────────────────────────────
Registration:
  1. privateKey = CSPRNG scalar (252 bits of entropy)
     publicKey  = privateKey · G

  2. wrappingKey = Argon2id(PIN, random_salt, m=64MB, t=3)
     ciphertext  = AES-256-GCM(wrappingKey, privateKey)
     Store encrypted blob → IndexedDB

  3. POST /auth/register { userId, publicKeyHex }
                                     ──────────►  Store publicKey

Login:
  1. Load blob from IndexedDB
     wrappingKey = Argon2id(PIN, stored_salt)
     privateKey  = AES-256-GCM.decrypt(ciphertext)

  2. POST /auth/challenge { userId } ──────────►  Issue challenge c (CSPRNG 32 bytes)
                          ◄──────────  Return c

  3. r = CSPRNG() — fresh nonce
     R = r · G
     s = r + SHA-512(R ∥ X ∥ c) · privateKey
     privateKey.fill(0)   ← zeroed here

     POST /auth/verify { userId, proofHex: R∥s }
                          ──────────►  Fetch publicKey for userId
                                       Verify: s·G == R + c·publicKey
                                       ✓  Issue JWT cookie
```

The server only ever stores the 32-byte **public key** — mathematically useless without the private scalar, which only the browser holds (encrypted, on-device).

Replay attacks are impossible: every challenge `c` is a fresh one-time nonce that expires server-side after a single use.

The crypto is built on [@noble/curves](https://github.com/paulmillr/noble-curves) and [@noble/hashes](https://github.com/paulmillr/noble-hashes) — audited, zero-dependency libraries. No custom crypto primitives.

For the full mathematical derivation and threat model, see the [Security Model docs](https://abhik2005.github.io/zkp-auth/security.html).

---

## Device transfer

One of the common questions with device-bound keys is: *"what happens when I get a new phone?"*

The library includes `exportKeyBlob` / `importKeyBlob` for this:

```ts
// On your current device:
const blob = await client.exportKeyBlob('alice', '123456');
// blob is opaque JSON — ciphertext, salt, iv. Safe to transmit.

// On your new device:
await client.importKeyBlob('alice', blob, '123456');
// Now the new device can log in with the same PIN and the same public key.
```

The blob is an AES-256-GCM ciphertext — the PIN verifies it before import.

---

## Get started

```bash
npm install @zkp-auth/server        # server
npm install @zkp-auth/client        # browser / vanilla JS
npm install @zkp-auth/client @zkp-auth/react  # React
```

- 📖 **Docs**: [abhik2005.github.io/zkp-auth](https://abhik2005.github.io/zkp-auth/)
- 🐙 **GitHub**: [github.com/Abhik2005/zkp-auth](https://github.com/Abhik2005/zkp-auth)
- 📦 **npm**: [`@zkp-auth/core`](https://www.npmjs.com/package/@zkp-auth/core)

> **Pre-1.0 notice**: This library has not yet undergone a formal third-party audit. Review the [security model](https://abhik2005.github.io/zkp-auth/security.html) before deploying to production.

Stars, issues, and PRs are all welcome. If you're building something with it, I'd love to hear about it in the comments.
