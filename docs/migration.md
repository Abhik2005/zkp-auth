# Migration Guide

Step-by-step guide for migrating an existing username/password application to ZKP Auth.

::: warning Before you start
ZKP Auth is **not a drop-in password replacement** — it changes the data model (no password hashes) and the client-side flow (browser derives a keypair). Plan a migration window and test thoroughly in a staging environment first.
:::

## Overview

| | Traditional auth | ZKP Auth |
|---|---|---|
| Server stores | `bcrypt(password)` | 32-byte Ed25519 public key |
| Login request body | `{ username, password }` | `{ userId, proofHex }` |
| Password on the wire | Yes (over HTTPS) | Never |
| Client library needed | No | Yes (`@zkp-auth/client`) |
| Session token | JWT / session cookie | JWT / session cookie (same) |
| Password reset | Email link → new hash | Email link → re-register |

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
} from '@zkp-auth/server';

const store = new InMemoryChallengeStore();

// New column in your users table: publicKey BYTEA (nullable during migration)
app.post(
  '/auth/zkp/register',
  zkpRegister({
    savePublicKey: async (userId, publicKey) => {
      await db.query(
        'UPDATE users SET zkp_public_key = $1 WHERE id = $2',
        [Buffer.from(publicKey), userId],
      );
    },
  }),
  (_req, res) => res.json({ ok: true }),
);

app.post(
  '/auth/zkp/challenge',
  zkpChallenge({ store }),
  (_req, res) => res.json({ challengeHex: res.locals.zkpChallengeHex }),
);

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

**After** (keypair derived in browser, only public key sent):

```tsx
import { useZKPAuth } from '@zkp-auth/react';

function RegisterForm() {
  const { register, loading, error } = useZKPAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    // register() derives the keypair and POSTs to /auth/zkp/register
    await register(
      f.get('username') as string,
      f.get('password') as string,
    );
  }

  return (
    <form onSubmit={handleSubmit}>
      <input name="username" required />
      <input name="password" type="password" />
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
    // login() fetches challenge → computes proof → posts to /auth/zkp/verify
    await login(
      f.get('username') as string,
      f.get('password') as string,
    );
  }

  if (isAuthenticated) return <p>Logged in!</p>;

  return (
    <form onSubmit={handleSubmit}>
      <input name="username" required />
      <input name="password" type="password" />
      <button disabled={loading}>{loading ? 'Authenticating…' : 'Log in'}</button>
      {error && <p>{error.message}</p>}
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
  const password = (document.getElementById('password') as HTMLInputElement).value;
  await client.register(username, password);
});

// Replace your old login handler
document.getElementById('login-btn')!.addEventListener('click', async () => {
  const username = (document.getElementById('username') as HTMLInputElement).value;
  const password = (document.getElementById('password') as HTMLInputElement).value;
  const { token } = await client.login(username, password);
  document.cookie = `auth=${token}; Secure; SameSite=Strict`;
});
```

## Phase 4 — Migrate existing users

Existing users have a password hash but no ZKP public key. You have two options:

### Option A — Prompt on next login (recommended)

Show a one-time banner after a successful legacy login prompting the user to "upgrade" their account. On confirmation, call `/auth/zkp/register` with the same credentials in the same session.

```tsx
function UpgradeBanner({ onUpgrade }: { onUpgrade: () => void }) {
  return (
    <div role="alert">
      <p>We've upgraded our security. Re-enter your password to activate ZKP login.</p>
      <button onClick={onUpgrade}>Upgrade now</button>
    </div>
  );
}

// After legacy login succeeds, check if zkp_public_key is set.
// If not, show the banner and call register() when the user confirms.
```

The user re-enters their password, the browser derives the keypair, and `/auth/zkp/register` stores the public key. From that point on the user is fully migrated.

### Option B — Force migration at cutover date

Set a deadline. After the deadline, old-style `/auth/login` returns `403` with a message directing users to re-register. This is simpler operationally but causes a forced interruption.

## Phase 5 — Remove legacy routes

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
- [ ] Update registration and login forms to use `useZKPAuth` (or `ZkpAuthClient`)
- [ ] Implement user migration flow (prompt-on-login or forced cutover)
- [ ] Confirm `SELECT COUNT(*) FROM users WHERE zkp_public_key IS NULL` → 0
- [ ] Rename `/auth/zkp/*` routes to `/auth/*`
- [ ] Drop `password_hash` column from users table
- [ ] Remove legacy auth middleware and routes
- [ ] Remove `bcrypt` (or equivalent) dependency from `package.json`
- [ ] Implement `IChallengeStore` backed by Redis/Postgres for multi-instance deployments
- [ ] Review the [Security Model](/security) page before go-live
