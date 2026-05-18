/**
 * @zkp-auth/server — public API surface
 *
 * Exports:
 *  - Three middleware factories: `zkpRegister`, `zkpChallenge`, `zkpVerify`
 *  - `InMemoryChallengeStore` (default implementation of `IChallengeStore`)
 *  - All typed error classes and codes
 *  - JWT helpers (`signJwt`, `verifyJwt`, `InvalidJwtError`)
 *  - All public option types and result types
 *
 * Import example:
 * ```ts
 * import {
 *   zkpRegister, zkpChallenge, zkpVerify,
 *   InMemoryChallengeStore,
 * } from '@zkp-auth/server';
 * ```
 */

// ---------------------------------------------------------------------------
// Side-effect import: wires the Express Request augmentation (req.zkpUser)
// ---------------------------------------------------------------------------
import './express-augmentation.js';

// ── Middleware factories ─────────────────────────────────────────────────────
export { zkpRegister } from './middleware/register.js';
export { zkpChallenge } from './middleware/challenge.js';
export { zkpVerify } from './middleware/verify.js';

// ── Challenge store ──────────────────────────────────────────────────────────
export { InMemoryChallengeStore } from './challenge-store.js';

// ── Typed errors ─────────────────────────────────────────────────────────────
export {
  ServerError,
  MissingFieldError,
  InvalidEncodingError,
  ChallengeNotFoundError,
  ChallengeExpiredError,
  ChallengeReplayedError,
  ProofInvalidError,
  PublicKeyNotFoundError,
  RateLimitedError,
  InternalError,
  toErrorBody,
} from './errors.js';
export type { ServerErrorCode, ErrorResponseBody } from './errors.js';

// ── JWT helpers ───────────────────────────────────────────────────────────────
export { signJwt, verifyJwt } from './jwt.js';
export type { ZkpJwtPayload } from './jwt.js';
export { InvalidJwtError } from './jwt-errors.js';

// ── Option / result types ─────────────────────────────────────────────────────
export type {
  IChallengeStore,
  RateLimitHook,
  GetPublicKeyFn,
  SavePublicKeyFn,
  ZkpRegisterOptions,
  ZkpChallengeOptions,
  ZkpVerifyOptions,
  ZkpUser,
  RegisterRequestBody,
  ChallengeRequestBody,
  VerifyRequestBody,
} from './types.js';

// ── Core handler result types (for callers building custom adapters) ───────────
export type { RegisterResult } from './core/register.js';
export type { ChallengeResult } from './core/challenge.js';
export type { VerifyResult } from './core/verify.js';

// ── Framework-agnostic core handlers (for non-Express adapters) ───────────────
export { handleRegister } from './core/register.js';
export { handleChallenge } from './core/challenge.js';
export { handleVerify } from './core/verify.js';
