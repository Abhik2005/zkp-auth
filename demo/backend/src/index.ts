/**
 * @zkp-auth/demo-backend — Express demo server
 *
 * Zero-configuration demo: no database, no environment variables.
 * Runs on http://localhost:3001 by default.
 *
 * Auth strategy:
 *   After successful ZKP verification, the JWT is stored in an HttpOnly
 *   cookie (never exposed to JavaScript). On every page load the frontend
 *   calls GET /api/me; if the cookie is valid, auth state is restored.
 *
 * Routes:
 *   GET  /api/pubkey      — health-check / server info
 *   POST /auth/register   — register userId + publicKeyHex
 *   POST /auth/challenge  — issue 32-byte challenge for userId
 *   POST /auth/verify     — verify Schnorr proof → set JWT cookie
 *   GET  /api/me          — read JWT cookie → return user info
 *   POST /api/logout      — clear JWT cookie
 *
 * Security note: cookie `secure: false` is intentional for local dev
 * (HTTP). Set to `true` behind HTTPS in production.
 */

import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import {
  zkpRegister,
  zkpChallenge,
  zkpVerify,
  InMemoryChallengeStore,
  verifyJwt,
  InvalidJwtError,
  toErrorBody,
  ServerError,
} from '@zkp-auth/server';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PORT = 3001;

/** Name of the session cookie. */
const COOKIE_NAME = 'zkp_session';

/**
 * Fixed demo JWT secret — 32 ASCII chars (256 bits).
 * DEMO ONLY. Never hardcode secrets in production.
 */
const DEMO_JWT_SECRET = 'zkp-auth-demo-secret-32-bytes!!!';

/** JWT lifetime in seconds (1 hour). Cookie maxAge matches. */
const JWT_EXPIRES_SECONDS = 3_600;

// ---------------------------------------------------------------------------
// In-memory user store (replaced by file persistence in Bug 2 fix)
// ---------------------------------------------------------------------------

/**
 * Maps userId → 32-byte Ed25519 public key.
 * Survives only for the lifetime of the process.
 */
const userStore = new Map<string, Uint8Array>();

/** Retrieve a registered public key, or `null` if unknown. */
async function getPublicKey(userId: string): Promise<Uint8Array | null> {
  return userStore.get(userId) ?? null;
}

/** Persist a user's Ed25519 public key (upsert). */
async function savePublicKey(userId: string, publicKey: Uint8Array): Promise<void> {
  userStore.set(userId, publicKey);
}

// ---------------------------------------------------------------------------
// Challenge store (shared between /auth/challenge and /auth/verify)
// ---------------------------------------------------------------------------

const challengeStore = new InMemoryChallengeStore();

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();

app.use(cors({
  origin: 'http://localhost:5173',   // Vite dev server
  credentials: true,                  // allow cookies to be sent cross-origin
}));
app.use(express.json());
app.use(cookieParser());

// ---------------------------------------------------------------------------
// Helper — set the session cookie
// ---------------------------------------------------------------------------

/**
 * Write the JWT into an HttpOnly cookie on the response.
 *
 * @param res    Express Response
 * @param token  Signed JWT string
 */
function setSessionCookie(res: Response, token: string): void {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: false,        // set true behind HTTPS in production
    sameSite: 'strict',
    maxAge: JWT_EXPIRES_SECONDS * 1_000,  // ms
  });
}

/**
 * Clear the session cookie.
 */
function clearSessionCookie(res: Response): void {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'strict' });
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/**
 * GET /api/pubkey
 * Health-check endpoint.
 */
app.get('/api/pubkey', (_req: Request, res: Response): void => {
  res.json({
    message: 'ZKP Auth demo server is running',
    version: '0.1.0',
    algorithm: 'Schnorr/Ed25519 with Fiat-Shamir (SHA-512)',
  });
});

/**
 * POST /auth/register
 * Body: { userId: string; publicKeyHex: string }
 *
 * `zkpRegister` is terminal — sends HTTP 201 itself.
 */
app.post('/auth/register', zkpRegister({ savePublicKey }));

/**
 * POST /auth/challenge
 * Body: { userId: string }
 *
 * `zkpChallenge` is terminal — sends HTTP 200 with { challengeHex } itself.
 */
app.post('/auth/challenge', zkpChallenge({ store: challengeStore }));

/**
 * POST /auth/verify
 * Body: { userId: string; proofHex: string }
 *
 * On success: sets an HttpOnly JWT cookie and returns { userId }.
 * The JWT is NOT returned in the response body — only in the cookie.
 */
app.post(
  '/auth/verify',
  zkpVerify({
    getPublicKey,
    store: challengeStore,
    jwtSecret: DEMO_JWT_SECRET,
    jwtExpiresInSeconds: JWT_EXPIRES_SECONDS,
  }),
  (req: Request, res: Response): void => {
    const token = res.locals['zkpToken'] as string;
    const userId = req.zkpUser!.userId;

    // Store JWT in HttpOnly cookie — never expose it to client JS.
    setSessionCookie(res, token);

    res.json({ userId });
  },
);

/**
 * GET /api/me
 *
 * Reads the HttpOnly JWT cookie, verifies it, and returns the user identity.
 * The frontend calls this on every page load to restore auth state.
 *
 * Returns:
 *   200 { userId: string; expiresAt: number }
 *   401 { error: ... }  — no cookie, expired, or invalid signature
 */
app.get('/api/me', (req: Request, res: Response): void => {
  const token: string | undefined = req.cookies[COOKIE_NAME] as string | undefined;

  if (token === undefined || token === '') {
    res.status(401).json({ error: { code: 'UNAUTHENTICATED', message: 'No session cookie' } });
    return;
  }

  try {
    const payload = verifyJwt(token, DEMO_JWT_SECRET);
    res.json({
      userId: payload.sub,
      expiresAt: payload.exp,
    });
  } catch (err) {
    if (err instanceof InvalidJwtError) {
      clearSessionCookie(res);   // clear the stale/invalid cookie
      res.status(401).json({ error: { code: 'INVALID_TOKEN', message: err.message } });
      return;
    }
    res.status(500).json({ error: { code: 'INTERNAL', message: 'Unexpected error' } });
  }
});

/**
 * POST /api/logout
 *
 * Clears the session cookie. No body required.
 * Always returns 200 — idempotent (safe to call even if not logged in).
 */
app.post('/api/logout', (_req: Request, res: Response): void => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Global error handler
// ---------------------------------------------------------------------------

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction): void => { // eslint-disable-line @typescript-eslint/no-unused-vars
  if (err instanceof ServerError) {
    res.status(err.httpStatus).json(toErrorBody(err));
    return;
  }
  console.error('[demo-backend] Unhandled error:', err);
  res.status(500).json({ error: { code: 'INTERNAL', message: 'Internal server error' } });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`\n🔐 ZKP Auth demo backend running at http://localhost:${PORT}`);
  console.log('   Routes:');
  console.log('     GET  /api/pubkey');
  console.log('     POST /auth/register');
  console.log('     POST /auth/challenge');
  console.log('     POST /auth/verify   → sets HttpOnly JWT cookie');
  console.log('     GET  /api/me        → reads cookie → returns user');
  console.log('     POST /api/logout    → clears cookie');
  console.log('\n   In-memory store — restarts clear all registered users.\n');
});
