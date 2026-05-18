---
layout: home

hero:
  name: "ZKP Auth"
  text: "Authentication without passwords"
  tagline: Schnorr Proof of Knowledge on Ed25519. Your password never leaves the browser — not even as a hash.
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
    title: Zero-Knowledge
    details: The server verifies you know your password without ever seeing it. No password hashes to steal.
  - icon: ⚡
    title: Drop-in for Express
    details: Three middleware functions. Mount them on your existing routes in under five minutes.
  - icon: ⚛️
    title: React-first
    details: A single hook — useZKPAuth() — gives you register, login, logout and reactive auth state.
  - icon: 🛡️
    title: No new crypto primitives
    details: Built on Ed25519 (battle-tested) and SHA-512. Uses @noble/curves — audited, zero-dependency.
---

# Getting Started

## What is ZKP Auth?

ZKP Auth lets users authenticate with a username and password **without the server ever seeing the password** — not even as a bcrypt hash.

Instead, the browser uses the password to derive an Ed25519 keypair and proves knowledge of the private key via a [Schnorr Proof of Knowledge](/how-it-works). The server stores only the 32-byte public key. No password database means no password database to breach.

### The three-package model

| Package | Role | Install target |
|---|---|---|
| `@zkp-auth/core` | Schnorr crypto primitives | Server (Node 20+) |
| `@zkp-auth/server` | Express middleware + JWT | Server |
| `@zkp-auth/client` | Browser SDK | Browser |
| `@zkp-auth/react` | React hooks + context | Browser |

## Why use this over normal password auth?

With traditional password authentication:

1. User types password → browser hashes or sends it in plain HTTPS.
2. Server stores `bcrypt(password)` in the database.
3. On login, server compares `bcrypt(attempt)` to stored hash.

**Attack surfaces:** database breach exposes all hashes; offline cracking converts weak hashes to passwords; rainbow tables, timing attacks.

With ZKP Auth:

1. Browser derives a keypair from the password (PBKDF2 / SHA-512).
2. Server stores only the 32-byte **public key** — mathematically useless without the private key.
3. On login, browser proves knowledge of the private key using a one-time Schnorr proof.

**Attack surfaces eliminated:** no hashes to steal, no offline cracking possible, replay attacks are provably impossible (each proof binds to a fresh server-issued challenge).

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
} from '@zkp-auth/server';

const app = express();
app.use(express.json());
app.use(cookieParser());

// In-memory store — swap for Redis/Postgres in production
const store = new InMemoryChallengeStore();

// In-memory user "database" — swap for your real DB
const users = new Map<string, Uint8Array>();

// Route 1 — register: save user's public key
app.post(
  '/auth/register',
  zkpRegister({
    savePublicKey: async (userId, publicKey) => {
      users.set(userId, publicKey);
    },
  }),
  (_req, res) => res.json({ ok: true }),
);

// Route 2 — challenge: issue a fresh one-time nonce
app.post(
  '/auth/challenge',
  zkpChallenge({ store }),
  (req, res) => res.json({ challengeHex: res.locals.zkpChallengeHex }),
);

// Route 3 — verify: check the proof, issue a JWT
app.post(
  '/auth/verify',
  zkpVerify({
    getPublicKey: async (userId) => users.get(userId) ?? null,
    store,
    jwtSecret: process.env.JWT_SECRET!,
  }),
  (req, res) => {
    // Set the JWT as an HttpOnly cookie
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
// LoginForm.tsx
import { useZKPAuth } from '@zkp-auth/react';

export function LoginForm() {
  const { register, login, logout, isAuthenticated, loading, error, user } =
    useZKPAuth();

  if (isAuthenticated) {
    return (
      <div>
        <p>Welcome, {user?.userId}!</p>
        <button onClick={logout}>Log out</button>
      </div>
    );
  }

  async function handleRegister(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    await register(
      form.get('username') as string,
      form.get('password') as string,
    );
  }

  async function handleLogin(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    await login(
      form.get('username') as string,
      form.get('password') as string,
    );
  }

  return (
    <>
      {error && <p style={{ color: 'red' }}>{error.message}</p>}

      <form onSubmit={handleRegister}>
        <h2>Register</h2>
        <input name="username" placeholder="Username" required />
        <input name="password" type="password" placeholder="Password" />
        <button type="submit" disabled={loading}>Register</button>
      </form>

      <form onSubmit={handleLogin}>
        <h2>Log in</h2>
        <input name="username" placeholder="Username" required />
        <input name="password" type="password" placeholder="Password" />
        <button type="submit" disabled={loading}>
          {loading ? 'Authenticating…' : 'Log in'}
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
- **[Migration Guide](/migration)** — migrating an existing username/password app.
