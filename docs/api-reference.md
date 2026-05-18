# API Reference

Complete reference for all four `@zkp-auth` packages.

## `@zkp-auth/core`

Low-level Schnorr crypto primitives. Use this directly only if you are building a custom server adapter or non-Express backend. Most users should use `@zkp-auth/server` and `@zkp-auth/client` instead.

```bash
npm install @zkp-auth/core
```

---

### `generateKeyPair()`

Generates a fresh Ed25519 keypair for the ZKP-auth scheme.

```ts
import { generateKeyPair } from '@zkp-auth/core';

function generateKeyPair(): {
  privateKey: Uint8Array; // 32 bytes, scalar in [1, L)
  publicKey: Uint8Array;  // 32 bytes, point encoding of privateKey · G
}
```

**Returns** an object with two fresh `Uint8Array` allocations.

**Throws**

| Error class | `.code` | Condition |
|---|---|---|
| `RandomnessError` | `'RNG_FAILURE'` | CSPRNG fault or rejection sampling exhausted 256 iterations |

**Example**

```ts
const { privateKey, publicKey } = generateKeyPair();
// Store publicKey on the server; keep privateKey in memory only.
// Zero-fill on logout:
privateKey.fill(0);
```

---

### `generateChallenge(sessionId)`

Generates a fresh 32-byte challenge for a Schnorr-proof session.

```ts
function generateChallenge(
  sessionId: Uint8Array, // 1–256 bytes; your session handle
): Uint8Array             // 32 fresh CSPRNG bytes, independent of sessionId
```

The returned bytes are **statistically independent** of `sessionId` — the parameter exists only for shape validation at the entry point. The challenge is cryptographically unpredictable.

**Throws**

| Error class | `.code` | Condition |
|---|---|---|
| `InvalidInputError` | `'INVALID_SESSION_ID'` | `sessionId` is not a `Uint8Array`, or length outside `[1, 256]` |
| `RandomnessError` | `'RNG_FAILURE'` | CSPRNG fault or short read |

**Example**

```ts
import { generateChallenge } from '@zkp-auth/core';

const sessionId = new TextEncoder().encode(userId);
const challenge = generateChallenge(sessionId);
// Store challenge server-side with a TTL, keyed by userId.
```

---

### `computeProof(privateKey, password, challenge)`

Computes a 64-byte Schnorr proof of knowledge of `privateKey` over a verifier-chosen `challenge`.

```ts
function computeProof(
  privateKey: Uint8Array, // 32 bytes, scalar in [1, L)
  password:   Uint8Array, // 0–4096 bytes (validated but currently unused in proof math)
  challenge:  Uint8Array, // 32 bytes, from generateChallenge()
): Uint8Array             // 64 bytes: R_bytes (32) || s_bytes (32)
```

The proof encodes `R = r·G` (the commitment) concatenated with the response scalar `s = (r + c·x) mod L`. The `password` parameter is validated for shape but **does not participate in the proof computation** — it is reserved for forward-compatible password-derived-key schemes.

**Throws**

| Error class | `.code` | Condition |
|---|---|---|
| `InvalidInputError` | `'INVALID_PRIVATE_KEY'` | Not `Uint8Array(32)`, or scalar is 0 or ≥ L |
| `InvalidInputError` | `'INVALID_PASSWORD'` | Not a `Uint8Array`, or length > 4096 |
| `InvalidInputError` | `'INVALID_CHALLENGE'` | Not `Uint8Array(32)` |
| `RandomnessError` | `'RNG_FAILURE'` | CSPRNG fault during nonce generation |

**Example**

```ts
import { computeProof } from '@zkp-auth/core';

const proof = computeProof(
  privateKey,
  new TextEncoder().encode(password),
  challengeBytes,
);
// proof is 64 bytes — send proofHex to the server
```

---

### `verifyProof(publicKey, challenge, proof)`

Verifies a 64-byte Schnorr proof against a registered public key and a one-time challenge.

```ts
function verifyProof(
  publicKey: Uint8Array, // 32 bytes, registered Ed25519 point
  challenge: Uint8Array, // 32 bytes, the challenge that was issued
  proof:     Uint8Array, // 64 bytes, R_bytes || s_bytes from computeProof()
): boolean               // true = valid proof; false = invalid/tampered
```

Returns `false` — never throws — for attacker-controlled proof material (malformed `R`, out-of-range `s`, wrong equation). This prevents oracle attacks that would let an adversary distinguish "malformed" from "mathematically invalid" proofs.

**Throws** (caller-side input errors only)

| Error class | `.code` | Condition |
|---|---|---|
| `InvalidInputError` | `'INVALID_PUBLIC_KEY'` | Not `Uint8Array(32)`, fails Edwards decode, or is the identity point |
| `InvalidInputError` | `'INVALID_CHALLENGE'` | Not `Uint8Array(32)` |
| `InvalidInputError` | `'INVALID_PROOF'` | Not `Uint8Array(64)` |

**Example**

```ts
import { verifyProof } from '@zkp-auth/core';

const valid = verifyProof(publicKey, challenge, proof);
if (!valid) {
  return res.status(401).json({ error: 'proof rejected' });
}
```

---

### Error classes

```ts
import { InvalidInputError, RandomnessError, CryptoError } from '@zkp-auth/core';
import type { ErrorCode } from '@zkp-auth/core';
```

All errors expose a stable `.code` discriminator — never parse `.message`.

```ts
type ErrorCode =
  | 'INVALID_PRIVATE_KEY'
  | 'INVALID_PUBLIC_KEY'
  | 'INVALID_CHALLENGE'
  | 'INVALID_PROOF'
  | 'INVALID_SESSION_ID'
  | 'INVALID_PASSWORD'
  | 'RNG_FAILURE'
  | 'CURVE_ERROR';
```

**Pattern matching**

```ts
import { InvalidInputError, RandomnessError } from '@zkp-auth/core';

try {
  const proof = computeProof(privateKey, password, challenge);
} catch (err) {
  if (err instanceof InvalidInputError) {
    console.error('bad input:', err.code);
  } else if (err instanceof RandomnessError) {
    console.error('CSPRNG fault:', err.code);
  }
}
```

---

## `@zkp-auth/server`

Express middleware for registration, challenge issuance, and proof verification. Includes JWT helpers and an in-memory challenge store.

```bash
npm install @zkp-auth/server
```

---

### `zkpRegister(options)`

Express middleware factory. Validates the request body, calls `savePublicKey`, and calls `next()` on success.

```ts
import { zkpRegister } from '@zkp-auth/server';

function zkpRegister(options: ZkpRegisterOptions): RequestHandler
```

**Request body** (`RegisterRequestBody`)

```ts
{
  userId:       string; // non-empty user identifier
  publicKeyHex: string; // 64 hex chars = 32-byte Ed25519 public key
}
```

**`ZkpRegisterOptions`**

```ts
interface ZkpRegisterOptions {
  /** Called with (userId, publicKey) after validation succeeds. */
  savePublicKey: (userId: string, publicKey: Uint8Array) => Promise<void>;
  /** Optional async rate-limit hook. Throw to block the request. */
  rateLimitHook?: (req: Request) => Promise<void>;
}
```

**Responses**

| Status | Condition |
|---|---|
| calls `next()` | success — route handler may send its own response |
| `400` | missing / malformed fields |
| `429` | `rateLimitHook` threw |
| `500` | `savePublicKey` threw unexpectedly |

**Example**

```ts
app.post(
  '/auth/register',
  zkpRegister({
    savePublicKey: async (userId, publicKey) => {
      await db.users.upsert({ userId, publicKey: Buffer.from(publicKey) });
    },
  }),
  (_req, res) => res.status(201).json({ ok: true }),
);
```

---

### `zkpChallenge(options)`

Issues a fresh 32-byte challenge, stores it in the challenge store with a TTL, and calls `next()`. Sets `res.locals.zkpChallengeHex` for the route handler.

```ts
function zkpChallenge(options: ZkpChallengeOptions): RequestHandler
```

**Request body** (`ChallengeRequestBody`)

```ts
{ userId: string }
```

**`ZkpChallengeOptions`**

```ts
interface ZkpChallengeOptions {
  /** Challenge store — must be the same instance passed to zkpVerify. */
  store: IChallengeStore;
  /** TTL in milliseconds. Default: 60_000 (60 s). */
  ttlMs?: number;
  rateLimitHook?: (req: Request) => Promise<void>;
}
```

**`res.locals` after success**

```ts
res.locals.zkpChallengeHex: string // 64 hex chars (32 bytes)
```

**Example**

```ts
app.post(
  '/auth/challenge',
  zkpChallenge({ store, ttlMs: 30_000 }),
  (req, res) => res.json({ challengeHex: res.locals.zkpChallengeHex }),
);
```

---

### `zkpVerify(options)`

Consumes the stored challenge, verifies the Schnorr proof, signs a JWT, and calls `next()`. Sets `req.zkpUser` and `res.locals.zkpToken`.

```ts
function zkpVerify(options: ZkpVerifyOptions): RequestHandler
```

**Request body** (`VerifyRequestBody`)

```ts
{
  userId:   string; // must match a stored public key
  proofHex: string; // 128 hex chars = 64-byte proof R_bytes || s_bytes
}
```

**`ZkpVerifyOptions`**

```ts
interface ZkpVerifyOptions {
  /** Look up the registered 32-byte public key for userId. Return null if not found. */
  getPublicKey: (userId: string) => Promise<Uint8Array | null>;
  /** Same store instance used in zkpChallenge. */
  store: IChallengeStore;
  /** HMAC-SHA256 secret. Must be ≥ 32 bytes when UTF-8 encoded. */
  jwtSecret: string;
  /** JWT expiry in seconds. Default: 3600 (1 hour). */
  jwtExpiresInSeconds?: number;
  rateLimitHook?: (req: Request) => Promise<void>;
}
```

**After success**

```ts
req.zkpUser            // { userId: string }
res.locals.zkpToken    // signed HS256 JWT string
```

**Responses**

| Status | Condition |
|---|---|
| calls `next()` | proof verified — handler reads `req.zkpUser` and `res.locals.zkpToken` |
| `400` | missing / malformed fields |
| `401` | no public key for user, challenge expired/not found, or proof invalid |
| `429` | rate limited |
| `500` | internal fault |

**Example**

```ts
app.post(
  '/auth/verify',
  zkpVerify({
    getPublicKey: async (userId) => db.users.getPublicKey(userId),
    store,
    jwtSecret: process.env.JWT_SECRET!,
    jwtExpiresInSeconds: 3600,
  }),
  (req, res) => {
    res.cookie('auth', res.locals.zkpToken, { httpOnly: true, sameSite: 'strict' });
    res.json({ userId: req.zkpUser!.userId });
  },
);
```

---

### `InMemoryChallengeStore`

Default `IChallengeStore` implementation. Suitable for single-process servers and development. For multi-instance deployments, supply a Redis-backed implementation.

```ts
import { InMemoryChallengeStore } from '@zkp-auth/server';

const store = new InMemoryChallengeStore();
```

**`IChallengeStore` interface** (implement to swap backends)

```ts
interface IChallengeStore {
  set(sessionId: string, challenge: Uint8Array, ttlMs: number): Promise<void>;
  consumeIfLive(sessionId: string): Promise<Uint8Array | null>;
}
```

`consumeIfLive` atomically retrieves **and deletes** the challenge — calling it twice always returns `null` on the second call.

---

### JWT helpers

```ts
import { signJwt, verifyJwt, InvalidJwtError } from '@zkp-auth/server';
import type { ZkpJwtPayload } from '@zkp-auth/server';
```

These are used internally by `zkpVerify`. You can use them directly to validate JWTs on protected routes.

```ts
// Sign
const token = await signJwt({ userId }, jwtSecret, { expiresInSeconds: 3600 });

// Verify (throws InvalidJwtError on failure)
const payload: ZkpJwtPayload = await verifyJwt(token, jwtSecret);
console.log(payload.userId);
```

```ts
interface ZkpJwtPayload {
  userId: string;
  iat: number;
  exp: number;
}
```

---

## `@zkp-auth/client`

Browser SDK. Wraps keypair derivation, proof computation, and HTTP calls into two async methods.

```bash
npm install @zkp-auth/client
```

---

### `ZkpAuthClient`

```ts
import { ZkpAuthClient } from '@zkp-auth/client';

const client = new ZkpAuthClient({ baseUrl: 'https://api.example.com' });
```

**Constructor options**

```ts
interface ZkpAuthClientOptions {
  /**
   * Base URL of the ZKP auth server.
   * Pass '' or '/' to use same-origin paths (Vite/webpack proxy).
   */
  baseUrl: string;
}
```

---

#### `client.register(username, password)`

```ts
async register(username: string, password: string): Promise<RegisterOutcome>

interface RegisterOutcome {
  userId:       string; // the registered username
  publicKeyHex: string; // 64 hex chars — 32-byte Ed25519 public key
}
```

Steps: derive keypair via PBKDF2 → POST `/auth/register` → cache private key in memory.

**Throws**

| Error class | `.code` | Condition |
|---|---|---|
| `ZkpCryptoError` | `'INVALID_USERNAME'` | Empty or > 256 UTF-8 bytes |
| `ZkpCryptoError` | `'INVALID_PASSWORD'` | > 4096 UTF-8 bytes |
| `ZkpCryptoError` | `'RNG_FAILURE'` | CSPRNG fault |
| `ZkpCryptoError` | `'CURVE_ERROR'` | Curve library internal error |
| `ZkpNetworkError` | — | `fetch()` rejected (network down) |
| `ZkpServerError` | `'REGISTER_FAILED'` | Server returned non-2xx |

---

#### `client.login(username, password)`

```ts
async login(username: string, password: string): Promise<LoginOutcome>

interface LoginOutcome {
  userId: string; // authenticated username
  token:  string; // signed HS256 JWT (empty string when server uses HttpOnly cookies)
}
```

Steps: re-derive key from PBKDF2 (or use cached key) → GET challenge → compute proof → POST `/auth/verify`.

**Throws**

| Error class | `.code` | Condition |
|---|---|---|
| `ZkpCryptoError` | `'INVALID_USERNAME'` | Empty or > 256 UTF-8 bytes |
| `ZkpCryptoError` | `'CURVE_ERROR'` | No key in memory, or curve error |
| `ZkpCryptoError` | `'RNG_FAILURE'` | CSPRNG fault during proof nonce |
| `ZkpNetworkError` | — | `fetch()` rejected |
| `ZkpServerError` | `'CHALLENGE_FAILED'` | Server did not issue challenge |
| `ZkpServerError` | `'PROOF_REJECTED'` | Proof verification failed |
| `ZkpServerError` | `'SERVER_ERROR'` | Unexpected server fault |

---

#### Key lifecycle methods

```ts
// true when a private key is held in memory
client.hasKey: boolean

// Zero-fill and discard the in-memory private key (call on logout)
client.clearKey(): void

// Load a previously exported key back (e.g. from encrypted IndexedDB)
client.loadKey(privateKey: Uint8Array): void

// Export a copy of the in-memory private key for out-of-band persistence
client.exportKey(): Uint8Array
```

---

#### Client error classes

```ts
import { ZkpClientError, ZkpCryptoError, ZkpNetworkError, ZkpServerError } from '@zkp-auth/client';
import type { ClientErrorCode } from '@zkp-auth/client';
```

All extend `ZkpClientError` and expose `.code`. Narrow with `instanceof`:

```ts
try {
  await client.login(username, password);
} catch (err) {
  if (err instanceof ZkpServerError && err.code === 'PROOF_REJECTED') {
    showError('Wrong username or password.');
  } else if (err instanceof ZkpNetworkError) {
    showError('Network unavailable — please try again.');
  }
}
```

---

## `@zkp-auth/react`

React bindings — a context provider and two hooks.

```bash
npm install @zkp-auth/client @zkp-auth/react
```

---

### `<ZKPProvider>`

Mount once near the root of your application. Creates a single `ZkpAuthClient` instance and provides auth state to the entire subtree.

```tsx
import { ZKPProvider } from '@zkp-auth/react';

interface ZKPProviderProps {
  options:  ZkpAuthClientOptions; // { baseUrl: string }
  children: ReactNode;
}
```

```tsx
// main.tsx
root.render(
  <ZKPProvider options={{ baseUrl: import.meta.env.VITE_API_URL }}>
    <App />
  </ZKPProvider>
);
```

::: warning One provider only
Mount `ZKPProvider` exactly once. Multiple providers create separate `ZkpAuthClient` instances with separate in-memory keys — logins in one subtree will not be visible in another.
:::

---

### `useZKPAuth()`

Primary hook. Returns all auth state and operations.

```ts
import { useZKPAuth } from '@zkp-auth/react';

function useZKPAuth(): ZKPAuthHookResult
```

**Return value** (`ZKPAuthHookResult = ZKPContextValue`)

```ts
interface ZKPContextValue {
  // ── State ──────────────────────────────────────────────────
  user:            ZKPUser | null;       // authenticated user, or null
  isAuthenticated: boolean;              // true after successful login()
  loading:         boolean;              // true while an op is in flight
  error:           ZkpClientError | null; // last error, or null

  // ── Operations ─────────────────────────────────────────────
  register(username: string, password: string): Promise<void>;
  login(username: string, password: string):    Promise<void>;
  logout(): void;
}

interface ZKPUser {
  userId:       string;
  token:        string | null; // JWT; null immediately after register()
  publicKeyHex: string | null; // hex public key; null after login-only session
}
```

**State transitions**

| Event | `user` | `isAuthenticated` | `loading` | `error` |
|---|---|---|---|---|
| Initial | `null` | `false` | `false` | `null` |
| `register()` starts | unchanged | `false` | **`true`** | `null` |
| `register()` succeeds | set (`token: null`) | `false` | `false` | `null` |
| `login()` starts | unchanged | unchanged | **`true`** | `null` |
| `login()` succeeds | set (`token: <jwt>`) | **`true`** | `false` | `null` |
| Any operation fails | unchanged | unchanged | `false` | **set** |
| `logout()` | `null` | `false` | `false` | `null` |

**Example**

```tsx
import { useZKPAuth } from '@zkp-auth/react';

function LoginForm() {
  const { login, loading, error, isAuthenticated, user } = useZKPAuth();

  if (isAuthenticated) return <p>Welcome, {user?.userId}</p>;

  return (
    <form onSubmit={async (e) => {
      e.preventDefault();
      const f = new FormData(e.currentTarget);
      await login(f.get('username') as string, f.get('password') as string);
    }}>
      <input name="username" required />
      <input name="password" type="password" />
      <button disabled={loading}>{loading ? 'Logging in…' : 'Log in'}</button>
      {error && <p role="alert">{error.message} ({error.code})</p>}
    </form>
  );
}
```

---

### `useZKPUser()`

Convenience hook. Returns `user` and `isAuthenticated` only — useful for read-only components that don't need operations.

```ts
import { useZKPUser } from '@zkp-auth/react';

function useZKPUser(): {
  user:            ZKPUser | null;
  isAuthenticated: boolean;
}
```

**Example**

```tsx
function Navbar() {
  const { user, isAuthenticated } = useZKPUser();
  return isAuthenticated ? <span>{user!.userId}</span> : <a href="/login">Log in</a>;
}
```

Both hooks **must be called inside a `<ZKPProvider>`** — they throw a descriptive error otherwise.
