# ZKP Auth Demo

End-to-end demonstration of Zero-Knowledge Proof authentication using
**Schnorr Proof of Knowledge on Ed25519** with the Fiat-Shamir transform.

No database. No environment variables. Works offline (after first install).

---

## Quick start (under 5 minutes)

```bash
# 1. Install all workspace dependencies (run from repo root)
pnpm install

# 2. Build the library packages the demo depends on
pnpm --filter @zkp-auth/core build
pnpm --filter @zkp-auth/server build
pnpm --filter @zkp-auth/client build
pnpm --filter @zkp-auth/react build

# 3. Start the backend (terminal 1)
cd demo/backend
pnpm dev

# 4. Start the frontend (terminal 2)
cd demo/frontend
pnpm dev
```

Open **http://localhost:5173** in your browser.

---

## How the demo works

### Auth flow

```
Browser                         Express (localhost:3001)
───────                         ──────────────────────────
Register page
  ├─ Generate Ed25519 keypair   (CSPRNG, in-browser WebCrypto)
  ├─ POST /auth/register ──────► store userId → publicKey in Map
  └─ Private key held in memory (never transmitted)

Login page
  ├─ POST /auth/challenge ─────► issue random 32-byte nonce
  ├─ Compute Schnorr proof      R = k·G, c = SHA-512(R‖pub‖nonce), s = k − c·priv
  ├─ POST /auth/verify ────────► verify proof with public key
  └─ Receive JWT ←─────────────  sign HS256 JWT { sub, iat, exp }

Dashboard
  ├─ Display username + JWT
  ├─ Decode JWT claims (client-side, for display only)
  └─ GET /api/me ──────────────► verify Bearer JWT → return { userId, iat, exp }
```

### Why ZKP?

The password never leaves the browser. The server never sees it, never stores it,
and cannot reconstruct it. The server only stores the Ed25519 public key and
verifies a mathematical proof that the client possesses the matching private key.

---

## Project structure

```
demo/
├── backend/
│   └── src/index.ts      Express server — in-memory user store
└── frontend/
    └── src/
        ├── main.tsx       ZKPProvider root
        ├── App.tsx        View router (Login / Register / Dashboard)
        ├── pages/
        │   ├── LoginPage.tsx
        │   ├── RegisterPage.tsx
        │   └── DashboardPage.tsx
        └── components/
            ├── icons.tsx
            └── Spinner.tsx
```

---

## Backend routes

| Method | Path              | Description                                          |
|--------|-------------------|------------------------------------------------------|
| GET    | `/api/pubkey`     | Health-check / server info                           |
| POST   | `/auth/register`  | Register `userId` + `publicKeyHex`                   |
| POST   | `/auth/challenge` | Issue 32-byte challenge for `userId`                 |
| POST   | `/auth/verify`    | Verify Schnorr proof; return `{ token, userId }`     |
| GET    | `/api/me`         | Decode Bearer JWT; return `{ userId, iat, exp }`     |

The `/auth/*` routes match the hardcoded paths in `@zkp-auth/client`.

---

## Notes

- **In-memory store only** — all users are lost when the backend restarts.
- **Hardcoded JWT secret** — `demo/backend/src/index.ts` line 41. Never do this in production.
- The Vite dev server proxies `/auth/*` and `/api/*` to `localhost:3001`, so
  no CORS headers are needed during development.
- After a page reload the private key is gone (JS heap only). Re-register or
  implement `ZkpAuthClient.exportKey()` + encrypted IndexedDB persistence.
