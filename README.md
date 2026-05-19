# ZKP Auth

[![npm version](https://img.shields.io/npm/v/@zkp-auth/core?label=%40zkp-auth%2Fcore&color=6366f1)](https://www.npmjs.com/package/@zkp-auth/core)
[![npm version](https://img.shields.io/npm/v/@zkp-auth/server?label=%40zkp-auth%2Fserver&color=6366f1)](https://www.npmjs.com/package/@zkp-auth/server)
[![npm version](https://img.shields.io/npm/v/@zkp-auth/client?label=%40zkp-auth%2Fclient&color=6366f1)](https://www.npmjs.com/package/@zkp-auth/client)
[![npm version](https://img.shields.io/npm/v/@zkp-auth/react?label=%40zkp-auth%2Freact&color=6366f1)](https://www.npmjs.com/package/@zkp-auth/react)
[![CI](https://github.com/Abhik2005/zkp-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/Abhik2005/zkp-auth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Truly passwordless Zero-Knowledge Proof authentication for TypeScript.** The server never sees a password — not even a hash. No password is ever derived, stored, or transmitted.

> Built on [Schnorr Proof of Knowledge](https://en.wikipedia.org/wiki/Proof_of_knowledge) over Ed25519 with the Fiat–Shamir transform, powered by [@noble/curves](https://github.com/paulmillr/noble-curves).

---

## Why ZKP Auth?

| Traditional Password Auth | ZKP Auth |
|---|---|
| Password sent to server (hashed or not) | **No password exists on the wire or server** |
| Server stores password hashes — breach = leak | Server stores only a public key — breach = nothing useful |
| Phishing can steal passwords | Phishing cannot extract a ZKP credential |
| Replay attacks possible with stolen hashes | Proofs are single-use and nonce-bound |
| MITM can intercept credentials | Credentials are cryptographic commitments, not secrets |
| Device-to-device login requires knowing password | Device transfer via encrypted key blob |

ZKP Auth implements an interactive Schnorr identification protocol with Fiat–Shamir heuristic:
1. Client generates a **random** Ed25519 keypair on registration — no password involved
2. The private key is encrypted with **Argon2id + AES-256-GCM** using a local PIN and stored in IndexedDB
3. On login, the PIN decrypts the key locally; the private key computes a Schnorr proof and is immediately zeroed
4. Server verifies `s·G = R + c·P` — no secret ever transmitted

---

## Packages

| Package | Description |
|---|---|
| [`@zkp-auth/core`](packages/zkp-auth-core) | Core crypto primitives — key generation, proof creation & verification |
| [`@zkp-auth/server`](packages/zkp-auth-server) | Express middleware — challenge issuance & proof verification endpoints |
| [`@zkp-auth/client`](packages/zkp-auth-client) | Browser SDK — random keypair, Argon2id local storage, proof construction |
| [`@zkp-auth/react`](packages/zkp-auth-react) | React hooks — `useZKPAuth()`, `useZKPUser()` |

---

## Quick Start

### Install

```bash
# Server
npm install @zkp-auth/server

# Browser / Bundler
npm install @zkp-auth/client

# React
npm install @zkp-auth/react @zkp-auth/client
```

### Server (Express)

```typescript
import express from 'express';
import {
  zkpRegister,
  zkpChallenge,
  zkpVerify,
  InMemoryChallengeStore,
} from '@zkp-auth/server';

const app = express();
app.use(express.json());

const store = new InMemoryChallengeStore();
const users = new Map<string, Uint8Array>();

app.post('/auth/register', zkpRegister({
  getPublicKey: async (userId) => users.get(userId) ?? null,
  savePublicKey: async (userId, publicKey) => { users.set(userId, publicKey); },
}));

app.post('/auth/challenge', zkpChallenge({ store }));

app.post('/auth/verify',
  zkpVerify({ getPublicKey: async (id) => users.get(id) ?? null, store, jwtSecret: process.env.JWT_SECRET! }),
  (req, res) => {
    res.cookie('auth', res.locals.zkpToken, { httpOnly: true, sameSite: 'strict' });
    res.json({ ok: true });
  },
);
```

### Client (Browser)

```typescript
import { ZkpAuthClient } from '@zkp-auth/client';

const client = new ZkpAuthClient({ baseUrl: 'https://api.example.com' });

// Register — generates a random keypair, encrypts it with the PIN locally,
// sends only the public key to the server. PIN is never transmitted.
await client.register('alice', '123456');

// Login — decrypts local key with PIN, computes Schnorr proof, gets JWT.
// PIN is never transmitted.
const { token } = await client.login('alice', '123456');
```

### React

```tsx
import { ZKPProvider, useZKPAuth } from '@zkp-auth/react';

// Wrap your app once:
// <ZKPProvider options={{ baseUrl: 'https://api.example.com' }}>

function LoginForm() {
  const { login, register, hasLocalKey, loading, error, isAuthenticated, user } = useZKPAuth();

  return (
    <form onSubmit={async (e) => {
      e.preventDefault();
      const f = new FormData(e.currentTarget);
      const username = f.get('username') as string;
      const pin      = f.get('pin') as string;
      const exists   = await hasLocalKey(username);
      exists ? await login(username, pin) : await register(username, pin);
    }}>
      <input name="username" />
      <input name="pin" type="password" placeholder="PIN (stays on device)" />
      <button disabled={loading}>Continue</button>
      {error && <p role="alert">{error.message}</p>}
    </form>
  );
}
```

---

## Documentation

Full documentation is available at **[abhik2005.github.io/zkp-auth](https://abhik2005.github.io/zkp-auth/)**:

- [Getting Started](docs/index.md)
- [How It Works](docs/how-it-works.md)
- [Security Model](docs/security.md)
- [API Reference](docs/api-reference.md)
- [Migration Guide](docs/migration.md)

### Run Docs Locally

```bash
pnpm install
pnpm docs:dev
# → http://localhost:5173
```

---

## Development

**Requirements:** Node.js ≥ 20, pnpm ≥ 9

```bash
git clone https://github.com/Abhik2005/zkp-auth.git
cd zkp-auth
pnpm install

pnpm build      # Build all packages
pnpm test       # Run all tests
pnpm typecheck  # TypeScript strict check
pnpm lint       # ESLint
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full contribution guidelines.

---

## Security

This library has not yet undergone a formal third-party audit. **Do not use in production for high-stakes applications without independent review.**

Found a vulnerability? Please follow the [responsible disclosure process](SECURITY.md).

---

## License

[MIT](LICENSE) © 2026 Abhik
