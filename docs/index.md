---
layout: home

hero:
  name: "ZKP Auth"
  text: "Authentication without passwords"
  tagline: Schnorr Proof of Knowledge on Ed25519. A random keypair lives on your device, encrypted by your PIN — the server stores only a public key, and nothing useful is ever sent over the wire.
  actions:
    - theme: brand
      text: Quick Start →
      link: "#quick-start"
    - theme: alt
      text: How It Works
      link: /how-it-works
    - theme: alt
      text: API Reference
      link: /api-reference

features:
  - icon: 🔐
    title: Truly Passwordless
    details: No password is ever derived, transmitted, or stored — not even a hash. A random Ed25519 key is generated on the device and encrypted locally with Argon2id.
  - icon: ⚡
    title: Drop-in for Express
    details: Three middleware functions. Mount them on your existing routes in under five minutes.
  - icon: ⚛️
    title: React-first
    details: A single hook — useZKPAuth() — gives you register, login, hasLocalKey, logout and reactive auth state.
  - icon: 🛡️
    title: No new crypto primitives
    details: Built on Ed25519, Argon2id, and AES-256-GCM. Uses @noble/curves and @noble/hashes — audited, zero-dependency.
---

# Getting Started

## What is ZKP Auth?

ZKP Auth lets users authenticate **without a password ever reaching the server** — not even as a bcrypt hash.

Instead, the browser generates a random Ed25519 keypair on first registration, encrypts the private key with **Argon2id + AES-256-GCM** using a local PIN, and stores the encrypted blob in IndexedDB. The server stores only the 32-byte public key. On login, the PIN decrypts the key locally, a Schnorr proof is computed, and the key is immediately zeroed. No password database means no password database to breach.

### The three-package model

| Package | Role | Install target |
|---|---|---|
| `@zkp-auth/core` | Schnorr crypto primitives | Server (Node 20+) |
| `@zkp-auth/server` | Express middleware + JWT | Server |
| `@zkp-auth/client` | Browser SDK — keypair, storage, proof | Browser |
| `@zkp-auth/react` | React hooks + context | Browser |

## Why use this over normal password auth?

With traditional password authentication:

1. User types password → browser hashes or sends it in plain HTTPS.
2. Server stores `bcrypt(password)` in the database.
3. On login, server compares `bcrypt(attempt)` to stored hash.

**Attack surfaces:** database breach exposes all hashes; offline cracking converts weak hashes to passwords; rainbow tables, timing attacks.

With ZKP Auth v0.2+:

1. Browser generates a **random** Ed25519 keypair — no password involved.
2. Private key is encrypted with Argon2id (64 MB memory wall) and stored in IndexedDB.
3. Server stores only the 32-byte **public key** — mathematically useless without the private scalar.
4. On login, browser decrypts the key with the PIN, proves knowledge via one-time Schnorr proof, zeroes the key.

**Attack surfaces eliminated:** no hashes to steal, no offline cracking possible, no password oracle, replay attacks are provably impossible (each proof binds to a fresh server-issued challenge).

::: tip When should I use it?
ZKP Auth is a good fit when you want strong security guarantees without building an OAuth/OIDC infrastructure. It is not a replacement for MFA or certificate-based auth, but it is a dramatic improvement over bcrypt-based password stores.
:::

::: warning Current status
This library is pre-1.0 and has **not been independently audited**. See the [Security Model](/security#audit-status) page for details. Use it in production only after your own security review.
:::

## Installation {#installation}

### Prerequisites

- Node.js ≥ 20
- pnpm ≥ 9 (npm and yarn also work)
- An existing Express server
- (Optional) A React application

### Server

```bash
npm install @zkp-auth/server
# or
pnpm add @zkp-auth/server
```

### Browser (vanilla JS)

```bash
npm install @zkp-auth/client
```

### Browser (React)

```bash
npm install @zkp-auth/client @zkp-auth/react
```

## Quick Start {#quick-start}

Get ZKP authentication running in five minutes.

### 1. Wire up the Express server

```ts
// server.ts
import express from 'express';
import cookieParser from 'cookie-parser';
import {
  zkpRegister,
  zkpChallenge,
  zkpVerify,
  InMemoryChallengeStore,
  RegistrationFailedError,
} from '@zkp-auth/server';

const app = express();
app.use(express.json());
app.use(cookieParser());

// In-memory store — swap for Redis/Postgres in production
const store = new InMemoryChallengeStore();

// In-memory user "database" — swap for your real DB
const users = new Map<string, Uint8Array>();

// Route 1 — register: stores the user's randomly generated public key
app.post(
  '/auth/register',
  zkpRegister({
    getPublicKey: async (userId) => users.get(userId) ?? null,
    savePublicKey: async (userId, publicKey) => {
      if (users.has(userId)) throw new RegistrationFailedError();
      users.set(userId, publicKey);
    },
  }),
);

// Route 2 — challenge: issue a fresh one-time nonce
app.post('/auth/challenge', zkpChallenge({ store }));

// Route 3 — verify: check the proof, issue a JWT
app.post(
  '/auth/verify',
  zkpVerify({
    getPublicKey: async (userId) => users.get(userId) ?? null,
    store,
    jwtSecret: process.env.JWT_SECRET!,
  }),
  (req, res) => {
    res.cookie('auth', res.locals.zkpToken, {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
    });
    res.json({ ok: true });
  },
);

app.listen(3001, () => console.log('ZKP auth server on :3001'));
```

### 2. Add the React provider

```tsx
// main.tsx
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { ZKPProvider } from '@zkp-auth/react';
import App from './App';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ZKPProvider options={{ baseUrl: 'http://localhost:3001' }}>
      <App />
    </ZKPProvider>
  </StrictMode>,
);
```

### 3. Use the hook

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

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const username = form.get('username') as string;
    const pin      = form.get('pin') as string;

    // Automatically routes to register or login based on device state
    const exists = await hasLocalKey(username);
    exists ? await login(username, pin) : await register(username, pin);
  }

  return (
    <>
      {error && <p style={{ color: 'red' }}>{error.message}</p>}

      <form onSubmit={handleSubmit}>
        <h2>Sign in</h2>
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
    </>
  );
}
```

That's it. No password is ever transmitted or stored on the server.

## Next steps

- **[How It Works](/how-it-works)** — understand the Schnorr proof and the full auth flow.
- **[API Reference](/api-reference)** — complete reference for all four packages.
- **[Security Model](/security)** — what is and isn't protected, known limitations.
- **[Migration Guide](/migration)** — migrating an existing username/password app to ZKP Auth.
