# ZKP Auth

[![npm version](https://img.shields.io/npm/v/@zkp-auth/core?label=%40zkp-auth%2Fcore&color=6366f1)](https://www.npmjs.com/package/@zkp-auth/core)
[![npm version](https://img.shields.io/npm/v/@zkp-auth/server?label=%40zkp-auth%2Fserver&color=6366f1)](https://www.npmjs.com/package/@zkp-auth/server)
[![npm version](https://img.shields.io/npm/v/@zkp-auth/client?label=%40zkp-auth%2Fclient&color=6366f1)](https://www.npmjs.com/package/@zkp-auth/client)
[![npm version](https://img.shields.io/npm/v/@zkp-auth/react?label=%40zkp-auth%2Freact&color=6366f1)](https://www.npmjs.com/package/@zkp-auth/react)
[![CI](https://github.com/Abhik2005/zkp-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/Abhik2005/zkp-auth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Zero-Knowledge Proof authentication for TypeScript.** Prove you know a secret without ever sending it — no passwords leave the client, ever.

> Built on [Schnorr Proof of Knowledge](https://en.wikipedia.org/wiki/Proof_of_knowledge) over Ed25519 with the Fiat–Shamir transform, powered by [@noble/curves](https://github.com/paulmillr/noble-curves).

---

## Why ZKP Auth?

| Traditional Password Auth | ZKP Auth |
|---|---|
| Password sent to server (hashed or not) | **Password never leaves the client** |
| Server stores password hashes — breach = leak | Server stores only a public key — breach = nothing useful |
| Phishing can steal passwords | Phishing cannot extract a ZKP credential |
| Replay attacks possible with stolen hashes | Proofs are single-use and nonce-bound |
| MITM can intercept credentials | Credentials are cryptographic commitments, not secrets |

ZKP Auth implements an interactive Schnorr identification protocol with Fiat–Shamir heuristic:
1. Client generates an ephemeral commitment `R`
2. Server issues a challenge `c = H(R ‖ pubKey ‖ message)`
3. Client computes a response `s = r + c·x` (where `x` is the private scalar)
4. Server verifies `s·G = R + c·P` — no secret ever transmitted

---

## Packages

| Package | Description |
|---|---|
| [`@zkp-auth/core`](packages/zkp-auth-core) | Core crypto primitives — key generation, proof creation & verification |
| [`@zkp-auth/server`](packages/zkp-auth-server) | Express middleware — challenge issuance & proof verification endpoints |
| [`@zkp-auth/client`](packages/zkp-auth-client) | Browser SDK — deterministic key derivation & proof construction |
| [`@zkp-auth/react`](packages/zkp-auth-react) | React hooks — `useZkpAuth`, `useZkpRegister` |

---

## Quick Start

### Install

```bash
# Server
npm install @zkp-auth/server @zkp-auth/core

# Browser / Bundler
npm install @zkp-auth/client @zkp-auth/core

# React
npm install @zkp-auth/react @zkp-auth/client @zkp-auth/core
```

### Server (Express)

```typescript
import express from 'express';
import { zkpAuthRouter } from '@zkp-auth/server';

const app = express();
app.use(express.json());

app.use('/auth', zkpAuthRouter({
  // Store and retrieve user public keys
  async getUser(username) {
    return db.users.findOne({ username });
  },
  async createUser(username, publicKey) {
    return db.users.create({ username, publicKey });
  },
  jwtSecret: process.env.JWT_SECRET!,
}));
```

### Client (Browser)

```typescript
import { ZkpClient } from '@zkp-auth/client';

const client = new ZkpClient({ baseUrl: 'https://api.example.com/auth' });

// Register — derives a deterministic key pair from password (never sent)
await client.register('alice', 'my-strong-password');

// Login — produces a ZK proof; password never transmitted
const { token } = await client.login('alice', 'my-strong-password');
```

### React

```tsx
import { useZkpAuth } from '@zkp-auth/react';

function LoginForm() {
  const { login, register, isLoading, error } = useZkpAuth({
    baseUrl: 'https://api.example.com/auth',
  });

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    await login(username, password);
    // Token stored; password gone from memory
  };

  return (
    <form onSubmit={handleLogin}>
      {/* ... */}
    </form>
  );
}
```

---

## Documentation

Full documentation is available at **[zkp-auth.dev](https://zkp-auth.dev)** (or run locally — see below):

- [Getting Started](docs/getting-started.md)
- [Security Model](docs/security.md)
- [API Reference](docs/api/)
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
