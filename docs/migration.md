# Migration Guide

Step-by-step guide for migrating an existing username/password application to ZKP Auth.

::: warning Before you start
ZKP Auth is **not a drop-in password replacement** — it changes the data model (no password hashes) and the client-side flow (browser generates a random keypair, stores it encrypted in IndexedDB). Plan a migration window and test thoroughly in a staging environment first.
:::

## Overview

| | Traditional auth | ZKP Auth |
|---|---|---|
| Server stores | `bcrypt(password)` | 32-byte Ed25519 public key |
| Login request body | `{ username, password }` | `{ userId, proofHex }` |
| Password on the wire | Yes (over HTTPS) | Never |
| Client secret | Password | PIN (local only — never transmitted) |
| Client library needed | No | Yes (`@zkp-auth/client`) |
| Session token | JWT / session cookie | JWT / session cookie (same) |
| Password reset | Email link → new hash | Email link → re-register |
| Multi-device | Same password everywhere | Key export blob or re-register per device |

The JWT / session cookie layer is identical — your protected routes and token validation code stay the same.

## Phase 1 — Install packages

### Server

```bash
npm install @zkp-auth/server
```

### Client (React)

```bash
npm install @zkp-auth/client @zkp-auth/react
```

### Client (vanilla JS)

```bash
npm install @zkp-auth/client
```

## Phase 2 — Add ZKP routes alongside existing routes

Run ZKP routes **in parallel** with your existing password routes during the transition. This lets you migrate users incrementally without a hard cutover.

```ts
// server.ts — add these alongside your existing /login, /register routes
import {
  zkpRegister,
  zkpChallenge,
  zkpVerify,
  InMemoryChallengeStore,
  RegistrationFailedError,
} from '@zkp-auth/server';

const store = new InMemoryChallengeStore();

// New column in your users table: zkp_public_key BYTEA (nullable during migration)
app.post(
  '/auth/zkp/register',
  zkpRegister({
    getPublicKey: async (userId) => {
      const row = await db.query(
        'SELECT zkp_public_key FROM users WHERE id = $1',
        [userId],
      );
      const key = row.rows[0]?.zkp_public_key;
      return key ? new Uint8Array(key) : null;
    },
    savePublicKey: async (userId, publicKey) => {
      const result = await db.query(
        'UPDATE users SET zkp_public_key = $1 WHERE id = $2 AND zkp_public_key IS NULL',
        [Buffer.from(publicKey), userId],
      );
      if (result.rowCount === 0) {
        throw new RegistrationFailedError();
      }
    },
  }),
);

app.post('/auth/zkp/challenge', zkpChallenge({ store }));

app.post(
  '/auth/zkp/verify',
  zkpVerify({
    getPublicKey: async (userId) => {
      const row = await db.query(
        'SELECT zkp_public_key FROM users WHERE id = $1',
        [userId],
      );
      const key = row.rows[0]?.zkp_public_key;
      return key ? new Uint8Array(key) : null;
    },
    store,
    jwtSecret: process.env.JWT_SECRET!,
  }),
  (req, res) => {
    res.cookie('auth', res.locals.zkpToken, { httpOnly: true, sameSite: 'strict' });
    res.json({ ok: true });
  },
);
```

### Database migration

Add a nullable `zkp_public_key` column. Users without a ZKP key continue to use the old password route until they re-register.

```sql
-- PostgreSQL example
ALTER TABLE users ADD COLUMN zkp_public_key BYTEA;
CREATE INDEX idx_users_zkp_public_key ON users (id) WHERE zkp_public_key IS NOT NULL;
```

The registration write must be create-only. For existing-user migrations, use
`WHERE zkp_public_key IS NULL` as shown above, or enforce the same rule with a
unique constraint / conditional insert in your datastore.

## Phase 3 — Update the client

### React

Replace your existing auth context / Redux slice with `ZKPProvider` and `useZKPAuth`.

**Before:**

```tsx
// Old auth wrapper
function App() {
  return (
    <AuthProvider>
      <Router />
    </AuthProvider>
  );
}
```

**After:**

```tsx
import { ZKPProvider } from '@zkp-auth/react';

function App() {
  return (
    <ZKPProvider options={{ baseUrl: import.meta.env.VITE_API_URL }}>
      <Router />
    </ZKPProvider>
  );
}
```

### Registration form

**Before** (sending password to server):

```tsx
async function handleRegister(username: string, password: string) {
  const res = await fetch('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  // ...
}
```

**After** (random keypair generated in browser; only public key sent):

```tsx
import { useZKPAuth } from '@zkp-auth/react';

function RegisterForm() {
  const { register, loading, error } = useZKPAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    // register() generates a random keypair, encrypts it with the PIN,
    // stores it in IndexedDB, and POSTs only the public key to /auth/zkp/register.
    // The PIN is never transmitted.
    await register(
      f.get('username') as string,
      f.get('pin') as string,
    );
  }

  return (
    <form onSubmit={handleSubmit}>
      <input name="username" required />
      <input name="pin" type="password" placeholder="Choose a PIN" />
      <button disabled={loading}>Register</button>
      {error && <p>{error.message}</p>}
    </form>
  );
}
```

### Login form

**Before:**

```tsx
async function handleLogin(username: string, password: string) {
  const res = await fetch('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  const { token } = await res.json();
  // store token...
}
```

**After:**

```tsx
function LoginForm() {
  const { login, loading, error, isAuthenticated } = useZKPAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    // login() decrypts the local key with PIN, computes a Schnorr proof,
    // and posts to /auth/zkp/verify. PIN is never transmitted.
    await login(
      f.get('username') as string,
      f.get('pin') as string,
    );
  }

  if (isAuthenticated) return <p>Logged in!</p>;

  return (
    <form onSubmit={handleSubmit}>
      <input name="username" required />
      <input name="pin" type="password" placeholder="Your PIN" />
      <button disabled={loading}>{loading ? 'Authenticating…' : 'Log in'}</button>
      {error && <p>{error.message}</p>}
    </form>
  );
}
```

### Adaptive form (recommended pattern)

Use `hasLocalKey` to automatically show the correct form without asking the user which one applies:

```tsx
function AuthForm() {
  const { register, login, hasLocalKey, loading, error } = useZKPAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const username = f.get('username') as string;
    const pin      = f.get('pin') as string;
    const exists   = await hasLocalKey(username);
    exists ? await login(username, pin) : await register(username, pin);
  }

  return (
    <form onSubmit={handleSubmit}>
      <input name="username" required />
      <input name="pin" type="password" placeholder="PIN (stays on device)" />
      <button disabled={loading}>{loading ? 'Working…' : 'Continue'}</button>
      {error && <p role="alert">{error.message}</p>}
    </form>
  );
}
```

### Vanilla JS (no React)

```ts
import { ZkpAuthClient } from '@zkp-auth/client';

const client = new ZkpAuthClient({ baseUrl: '/api' });

// Replace your old register handler
document.getElementById('register-btn')!.addEventListener('click', async () => {
  const username = (document.getElementById('username') as HTMLInputElement).value;
  const pin      = (document.getElementById('pin') as HTMLInputElement).value;
  await client.register(username, pin);
});

// Replace your old login handler
document.getElementById('login-btn')!.addEventListener('click', async () => {
  const username = (document.getElementById('username') as HTMLInputElement).value;
  const pin      = (document.getElementById('pin') as HTMLInputElement).value;
  const { token } = await client.login(username, pin);
  document.cookie = `auth=${token}; Secure; SameSite=Strict`;
});
```

## Phase 4 — Migrate existing users

Existing users have a password hash but no ZKP public key. You have two options:

### Option A — Prompt on next login (recommended)

Show a one-time banner after a successful legacy login prompting the user to "upgrade" their account. On confirmation:

1. The user enters a new PIN.
2. `register()` generates a random keypair, encrypts it with the PIN, and POSTs the public key to `/auth/zkp/register`.
3. From that point, the user logs in with their PIN on this device.

```tsx
function UpgradeBanner({ username, onUpgrade }: { username: string; onUpgrade: () => void }) {
  return (
    <div role="alert">
      <p>We've upgraded our security. Set a PIN to activate ZKP login on this device.</p>
      <button onClick={onUpgrade}>Upgrade now</button>
    </div>
  );
}

// After legacy login succeeds, check if zkp_public_key is set.
// If not, show the banner and call register(username, pin) when the user confirms.
```

Unlike the old PBKDF2-based migration (where the password was re-used to derive the key), the new flow asks the user to **choose a PIN** — it does not require them to enter their old password.

### Option B — Force migration at cutover date

Set a deadline. After the deadline, old-style `/auth/login` returns `403` with a message directing users to re-register. This is simpler operationally but causes a forced interruption.

## Phase 5 — Multi-device users

Each device generates its own random keypair, meaning a user who registers on Device A cannot log in on Device B without one of:

1. **Re-registering on Device B** — generates a new keypair; the old Device A key remains valid in parallel. The server stores only one public key per user by default; implement per-device public key storage if parallel devices are needed.
2. **Key transfer via blob** — export the Device A key as a JSON blob and import it on Device B:

```ts
// On Device A:
const blob = await client.exportKeyBlob('alice', '123456');
// Transfer blob (e.g. QR code, encrypted email, AirDrop)

// On Device B:
await client.importKeyBlob('alice', blob, '123456');
// Now Device B can log in with the same PIN and the same public key.
```

## Phase 6 — Remove legacy routes

Once all users have a `zkp_public_key` (verify with a database query), remove the old password routes and the `password_hash` column.

```sql
-- Verify: no users without a ZKP key remain
SELECT COUNT(*) FROM users WHERE zkp_public_key IS NULL;
-- → 0

-- Rename ZKP routes to canonical paths
-- /auth/zkp/register → /auth/register
-- /auth/zkp/challenge → /auth/challenge
-- /auth/zkp/verify → /auth/verify

-- Drop the old column
ALTER TABLE users DROP COLUMN password_hash;
```

Update the client `baseUrl` paths to drop the `/zkp` prefix (or update your route definitions server-side).

## Protected routes — nothing changes

Your existing JWT validation middleware doesn't need to change. `zkpVerify` issues standard HS256 JWTs with the same `{ userId, iat, exp }` payload shape — your protected routes continue to read `req.user.userId` (or equivalent) exactly as before.

```ts
// This middleware works identically before and after migration
function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = req.cookies.auth;
  if (!token) return res.status(401).end();
  const payload = verifyJwt(token, process.env.JWT_SECRET!);
  req.user = payload; // { userId, iat, exp }
  next();
}
```

## Migration checklist

- [ ] Add `zkp_public_key BYTEA` column (nullable) to users table
- [ ] Deploy ZKP routes at `/auth/zkp/*` alongside existing routes
- [ ] Wrap the React app with `<ZKPProvider>`
- [ ] Update registration and login forms to use `useZKPAuth` (or `ZkpAuthClient`) with PIN
- [ ] Implement user migration flow (prompt-on-login or forced cutover)
- [ ] Document multi-device policy and implement `exportKeyBlob` / `importKeyBlob` if needed
- [ ] Confirm `SELECT COUNT(*) FROM users WHERE zkp_public_key IS NULL` → 0
- [ ] Rename `/auth/zkp/*` routes to `/auth/*`
- [ ] Drop `password_hash` column from users table
- [ ] Remove legacy auth middleware and routes
- [ ] Remove `bcrypt` (or equivalent) dependency from `package.json`
- [ ] Implement `IChallengeStore` backed by Redis/Postgres for multi-instance deployments
- [ ] Review the [Security Model](/security) page before go-live
