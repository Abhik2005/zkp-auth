/**
 * Integration tests for zkp-auth-server Express middleware.
 *
 * Uses Supertest to drive a real Express app (no network socket).
 * All crypto uses actual @zkp-auth/core — no mocking of crypto primitives.
 *
 * Coverage:
 *  Register:
 *   - 201 on valid registration
 *   - 400 missing userId
 *   - 400 missing publicKeyHex
 *   - 400 invalid hex (wrong length)
 *   - 400 invalid Ed25519 point (all-zeros key is the identity point)
 *
 *  Challenge:
 *   - 200 challenge_issued with hex + expiresInMs
 *   - 400 missing userId
 *   - 429 when rate-limit hook rejects
 *
 *  Verify:
 *   - 200 (via next()) and token in res.locals on valid proof
 *   - req.zkpUser populated on success
 *   - 400 missing userId
 *   - 400 missing proofHex
 *   - 400 invalid proofHex encoding
 *   - 401 public key not found
 *   - 400 challenge expired / not found
 *   - 400 replay attack — second verify with same challenge returns error
 *   - 401 wrong proof
 *
 *  Error shape:
 *   - All errors return { error: { code, message } }
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import express, { type Express } from 'express';
import request from 'supertest';
import { generateKeyPair, generateChallenge, computeProof } from '@zkp-auth/core';
import {
  zkpRegister,
  zkpChallenge,
  zkpVerify,
  zkpRekey,
  InMemoryChallengeStore,
  createAuditLogger,
  createRateLimiter,
  createRegistrationRateLimiter,
  RegistrationFailedError,
} from '../src/index.js';
import type { IChallengeStore } from '../src/index.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const JWT_SECRET = 'super-secret-key-at-least-32-bytes!';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal Express app wired with all three middleware. */
function buildApp(store: IChallengeStore, keyDb: Map<string, Uint8Array>): Express {
  const app = express();
  app.use(express.json());

  const authRateLimiter = createRateLimiter();
  const registrationRateLimiter = createRegistrationRateLimiter();
  const noopAuditLogger = createAuditLogger({
    write: () => undefined,
  });

  app.post(
    '/auth/register',
    zkpRegister({
      getPublicKey: async (userId) => keyDb.get(userId) ?? null,
      savePublicKey: async (userId, key) => {
        if (keyDb.has(userId)) {
          throw new RegistrationFailedError();
        }
        keyDb.set(userId, key);
      },
      minRegisterResponseMs: 0,
      auditLogger: noopAuditLogger,
      registrationRateLimiter,
    }),
  );

  app.post('/auth/challenge', zkpChallenge({ store, authRateLimiter }));

  app.post(
    '/auth/verify',
    zkpVerify({
      getPublicKey: async (userId) => keyDb.get(userId) ?? null,
      store,
      jwtSecret: JWT_SECRET,
      authRateLimiter,
    }),
    // Route handler that sends the token — verifyMiddleware calls next() on success.
    (req, res) => {
      res.status(200).json({
        status: 'verified',
        token: res.locals['zkpToken'] as string,
        userId: req.zkpUser?.userId,
      });
    },
  );

  app.post(
    '/auth/rekey',
    zkpRekey({
      getPublicKey: async (userId) => keyDb.get(userId) ?? null,
      savePublicKey: async (userId, key) => {
        keyDb.set(userId, key);
      },
      store,
      authRateLimiter,
    }),
  );

  return app;
}

/** Run a full register → challenge → prove → verify flow for a user. */
async function fullFlow(
  app: Express,
  userId: string,
): Promise<{ token: string; challengeHex: string; proofHex: string }> {
  const { privateKey, publicKey } = generateKeyPair();

  // Register
  await request(app)
    .post('/auth/register')
    .send({ userId, publicKeyHex: Buffer.from(publicKey).toString('hex') })
    .expect(201);

  // Challenge
  const challengeRes = await request(app).post('/auth/challenge').send({ userId }).expect(200);
  const { challengeHex } = challengeRes.body as { challengeHex: string };

  // Prove
  const challengeBytes = Uint8Array.from(Buffer.from(challengeHex, 'hex'));
  const proof = computeProof(privateKey, new Uint8Array(0), challengeBytes);
  const proofHex = Buffer.from(proof).toString('hex');

  // Verify
  const verifyRes = await request(app).post('/auth/verify').send({ userId, proofHex }).expect(200);

  return {
    token: (verifyRes.body as { token: string }).token,
    challengeHex,
    proofHex,
  };
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

let store: InMemoryChallengeStore;
let keyDb: Map<string, Uint8Array>;
let app: Express;

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  store = new InMemoryChallengeStore();
  keyDb = new Map();
  app = buildApp(store, keyDb);
});

afterEach(() => {
  store.destroy();
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// Register tests
// ---------------------------------------------------------------------------

describe('POST /auth/register', () => {
  it('register_validKeyPair_returns201WithStatus', async () => {
    const { publicKey } = generateKeyPair();
    const res = await request(app)
      .post('/auth/register')
      .send({ userId: 'alice', publicKeyHex: Buffer.from(publicKey).toString('hex') })
      .expect(201);

    expect((res.body as { status: string }).status).toBe('registered');
    expect((res.body as { userId: string }).userId).toBe('alice');
  });

  it('register_missingUserId_returns400MissingField', async () => {
    const { publicKey } = generateKeyPair();
    const res = await request(app)
      .post('/auth/register')
      .send({ publicKeyHex: Buffer.from(publicKey).toString('hex') })
      .expect(400);

    expect((res.body as { error: { code: string } }).error.code).toBe('MISSING_FIELD');
  });

  it('register_missingPublicKeyHex_returns400MissingField', async () => {
    const res = await request(app).post('/auth/register').send({ userId: 'alice' }).expect(400);

    expect((res.body as { error: { code: string } }).error.code).toBe('MISSING_FIELD');
  });

  it('register_shortHex_returns400InvalidEncoding', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({ userId: 'alice', publicKeyHex: 'deadbeef' }) // only 8 chars, need 64
      .expect(400);

    expect((res.body as { error: { code: string } }).error.code).toBe('INVALID_ENCODING');
  });

  it('register_invalidPoint_returns400InvalidEncoding', async () => {
    // Ed25519 identity point (0, 1): little-endian y=1 with x=0.
    // Encoding: 0x01 followed by 31 zero bytes.
    // verifyProof throws INVALID_PUBLIC_KEY for identity points.
    const identityBytes = new Uint8Array(32);
    identityBytes[0] = 0x01;
    const identityHex = Buffer.from(identityBytes).toString('hex');

    const res = await request(app)
      .post('/auth/register')
      .send({ userId: 'alice', publicKeyHex: identityHex })
      .expect(400);

    expect((res.body as { error: { code: string } }).error.code).toBe('INVALID_ENCODING');
  });

  it('register_sameUserTwice_secondCallRejectsWithoutOverwritingKey', async () => {
    const { publicKey } = generateKeyPair();
    const attacker = generateKeyPair();
    const hex = Buffer.from(publicKey).toString('hex');
    const attackerHex = Buffer.from(attacker.publicKey).toString('hex');

    await request(app)
      .post('/auth/register')
      .send({ userId: 'alice', publicKeyHex: hex })
      .expect(201);
    const res = await request(app)
      .post('/auth/register')
      .send({ userId: 'alice', publicKeyHex: attackerHex })
      .expect(409);

    expect((res.body as { error: { code: string; message: string } }).error.code).toBe(
      'REGISTRATION_FAILED',
    );
    expect((res.body as { error: { code: string; message: string } }).error.message).toBe(
      'registration failed',
    );
    expect(Buffer.from(keyDb.get('alice') ?? new Uint8Array()).toString('hex')).toBe(hex);
  });

  it('register_storageDuplicateConflict_returns409WithoutOverwritingKey', async () => {
    const { publicKey } = generateKeyPair();
    const attacker = generateKeyPair();
    const hex = Buffer.from(publicKey).toString('hex');
    const attackerHex = Buffer.from(attacker.publicKey).toString('hex');
    let lookupCount = 0;

    const raceApp = express();
    raceApp.use(express.json());
    raceApp.post(
      '/auth/register',
      zkpRegister({
        getPublicKey: async () => {
          lookupCount += 1;
          return lookupCount === 1 ? null : publicKey;
        },
        savePublicKey: async () => {
          throw new RegistrationFailedError();
        },
        minRegisterResponseMs: 0,
        auditLogger: createAuditLogger({ write: () => undefined }),
        registrationRateLimiter: createRegistrationRateLimiter(),
      }),
    );

    keyDb.set('alice', publicKey);

    const res = await request(raceApp)
      .post('/auth/register')
      .send({ userId: 'alice', publicKeyHex: attackerHex })
      .expect(409);

    expect((res.body as { error: { code: string; message: string } }).error.code).toBe(
      'REGISTRATION_FAILED',
    );
    expect((res.body as { error: { code: string; message: string } }).error.message).toBe(
      'registration failed',
    );
    expect(Buffer.from(keyDb.get('alice') ?? new Uint8Array()).toString('hex')).toBe(hex);
  });
});

// ---------------------------------------------------------------------------
// Challenge tests
// ---------------------------------------------------------------------------

describe('POST /auth/challenge', () => {
  it('challenge_validUserId_returns200WithHexAndExpiry', async () => {
    const res = await request(app).post('/auth/challenge').send({ userId: 'alice' }).expect(200);

    const body = res.body as { status: string; challengeHex: string; expiresInMs: number };
    expect(body.status).toBe('challenge_issued');
    expect(body.challengeHex).toMatch(/^[0-9a-f]{64}$/);
    expect(body.expiresInMs).toBe(60_000);
  });

  it('challenge_missingUserId_returns400', async () => {
    const res = await request(app).post('/auth/challenge').send({}).expect(400);

    expect((res.body as { error: { code: string } }).error.code).toBe('MISSING_FIELD');
  });

  it('challenge_rateLimitHook_returns429', async () => {
    const limitedApp = express();
    limitedApp.use(express.json());
    limitedApp.post(
      '/auth/challenge',
      zkpChallenge({
        store,
        rateLimitHook: async () => {
          throw new Error('too many');
        },
      }),
    );

    const res = await request(limitedApp)
      .post('/auth/challenge')
      .send({ userId: 'alice' })
      .expect(429);

    expect((res.body as { error: { code: string } }).error.code).toBe('RATE_LIMITED');
  });

  it('challenge_calledTwice_secondChallengeReplaceFirst', async () => {
    const res1 = await request(app).post('/auth/challenge').send({ userId: 'alice' }).expect(200);
    const res2 = await request(app).post('/auth/challenge').send({ userId: 'alice' }).expect(200);

    const hex1 = (res1.body as { challengeHex: string }).challengeHex;
    const hex2 = (res2.body as { challengeHex: string }).challengeHex;

    // Statistically guaranteed to differ (32 random bytes)
    expect(hex1).not.toBe(hex2);
  });
});

// ---------------------------------------------------------------------------
// Verify tests
// ---------------------------------------------------------------------------

describe('POST /auth/verify', () => {
  it('verify_validProof_returns200WithToken', async () => {
    const { token } = await fullFlow(app, 'alice');
    expect(typeof token).toBe('string');
    expect(token.split('.')).toHaveLength(3);
  });

  it('verify_validProof_reqZkpUserPopulated', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const userId = 'bob';

    await request(app)
      .post('/auth/register')
      .send({ userId, publicKeyHex: Buffer.from(publicKey).toString('hex') })
      .expect(201);

    const challengeRes = await request(app).post('/auth/challenge').send({ userId }).expect(200);
    const challengeHex = (challengeRes.body as { challengeHex: string }).challengeHex;

    const challengeBytes = Uint8Array.from(Buffer.from(challengeHex, 'hex'));
    const proof = computeProof(privateKey, new Uint8Array(0), challengeBytes);
    const proofHex = Buffer.from(proof).toString('hex');

    const verifyRes = await request(app)
      .post('/auth/verify')
      .send({ userId, proofHex })
      .expect(200);

    expect((verifyRes.body as { userId: string }).userId).toBe(userId);
  });

  it('verify_missingUserId_returns400', async () => {
    const res = await request(app)
      .post('/auth/verify')
      .send({ proofHex: 'a'.repeat(128) })
      .expect(400);

    expect((res.body as { error: { code: string } }).error.code).toBe('MISSING_FIELD');
  });

  it('verify_missingProofHex_returns400', async () => {
    const res = await request(app).post('/auth/verify').send({ userId: 'alice' }).expect(400);

    expect((res.body as { error: { code: string } }).error.code).toBe('MISSING_FIELD');
  });

  it('verify_invalidProofHexEncoding_returns400', async () => {
    const res = await request(app)
      .post('/auth/verify')
      .send({ userId: 'alice', proofHex: 'gg'.repeat(64) }) // not valid hex
      .expect(400);

    expect((res.body as { error: { code: string } }).error.code).toBe('INVALID_ENCODING');
  });

  it('verify_unknownUser_returns401PublicKeyNotFound', async () => {
    // Issue a challenge for an unregistered user so we have a live challenge.
    await request(app).post('/auth/challenge').send({ userId: 'ghost' });

    const res = await request(app)
      .post('/auth/verify')
      .send({ userId: 'ghost', proofHex: 'a'.repeat(128) })
      .expect(401);

    expect((res.body as { error: { code: string } }).error.code).toBe('PUBLIC_KEY_NOT_FOUND');
  });

  it('verify_noChallengeIssued_returns400ChallengeExpired', async () => {
    const { publicKey } = generateKeyPair();
    await request(app)
      .post('/auth/register')
      .send({ userId: 'alice', publicKeyHex: Buffer.from(publicKey).toString('hex') })
      .expect(201);

    // No /challenge call — go straight to /verify
    const res = await request(app)
      .post('/auth/verify')
      .send({ userId: 'alice', proofHex: 'a'.repeat(128) })
      .expect(400);

    expect((res.body as { error: { code: string } }).error.code).toBe('CHALLENGE_EXPIRED');
  });

  it('verify_challengeExpired_returns400', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const userId = 'alice';
    await request(app)
      .post('/auth/register')
      .send({ userId, publicKeyHex: Buffer.from(publicKey).toString('hex') })
      .expect(201);

    // Issue with a 5-second TTL
    const shortStore = new InMemoryChallengeStore();
    const shortApp = buildApp(shortStore, keyDb);
    const challengeRes = await request(shortApp).post('/auth/challenge').send({ userId });
    const challengeHex = (challengeRes.body as { challengeHex: string }).challengeHex;

    // Advance past TTL
    vi.advanceTimersByTime(61_000);

    const challengeBytes = Uint8Array.from(Buffer.from(challengeHex, 'hex'));
    const proof = computeProof(privateKey, new Uint8Array(0), challengeBytes);

    const res = await request(shortApp)
      .post('/auth/verify')
      .send({ userId, proofHex: Buffer.from(proof).toString('hex') })
      .expect(400);

    expect((res.body as { error: { code: string } }).error.code).toBe('CHALLENGE_EXPIRED');
    shortStore.destroy();
  });

  it('verify_replayAttack_secondVerifyFails', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const userId = 'alice';

    await request(app)
      .post('/auth/register')
      .send({ userId, publicKeyHex: Buffer.from(publicKey).toString('hex') })
      .expect(201);

    const challengeRes = await request(app).post('/auth/challenge').send({ userId }).expect(200);
    const challengeHex = (challengeRes.body as { challengeHex: string }).challengeHex;
    const challengeBytes = Uint8Array.from(Buffer.from(challengeHex, 'hex'));
    const proof = computeProof(privateKey, new Uint8Array(0), challengeBytes);
    const proofHex = Buffer.from(proof).toString('hex');

    // First verify succeeds
    await request(app).post('/auth/verify').send({ userId, proofHex }).expect(200);

    // Second verify with the SAME proof must fail (challenge already consumed)
    const res = await request(app).post('/auth/verify').send({ userId, proofHex }).expect(400);

    expect((res.body as { error: { code: string } }).error.code).toBe('CHALLENGE_EXPIRED');
  });

  it('verify_wrongProof_returns401ProofInvalid', async () => {
    const { publicKey } = generateKeyPair();
    const userId = 'alice';

    await request(app)
      .post('/auth/register')
      .send({ userId, publicKeyHex: Buffer.from(publicKey).toString('hex') })
      .expect(201);

    await request(app).post('/auth/challenge').send({ userId }).expect(200);

    // Generate proof with a different key pair — it won't verify
    const { privateKey: wrongKey } = generateKeyPair();
    const fakeChallenge = generateChallenge(new TextEncoder().encode(userId));
    const wrongProof = computeProof(wrongKey, new Uint8Array(0), fakeChallenge);

    const res = await request(app)
      .post('/auth/verify')
      .send({ userId, proofHex: Buffer.from(wrongProof).toString('hex') })
      .expect(401);

    expect((res.body as { error: { code: string } }).error.code).toBe('PROOF_INVALID');
  });

  it('verify_rateLimitHook_returns429', async () => {
    const limitedApp = express();
    limitedApp.use(express.json());
    limitedApp.post(
      '/auth/verify',
      zkpVerify({
        getPublicKey: async () => null,
        store,
        jwtSecret: JWT_SECRET,
        rateLimitHook: async () => {
          throw new Error('blocked');
        },
      }),
    );

    const res = await request(limitedApp)
      .post('/auth/verify')
      .send({ userId: 'alice', proofHex: 'a'.repeat(128) })
      .expect(429);

    expect((res.body as { error: { code: string } }).error.code).toBe('RATE_LIMITED');
  });
});

// ---------------------------------------------------------------------------
// Error shape contract
// ---------------------------------------------------------------------------

describe('Error response shape', () => {
  it('allErrors_haveCodeAndMessage', async () => {
    const res = await request(app).post('/auth/register').send({}).expect(400);

    const body = res.body as { error: { code: string; message: string } };
    expect(typeof body.error.code).toBe('string');
    expect(typeof body.error.message).toBe('string');
    expect(body.error.code.length).toBeGreaterThan(0);
    expect(body.error.message.length).toBeGreaterThan(0);
  });
});
