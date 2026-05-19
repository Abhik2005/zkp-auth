/**
 * @zkp-auth/server — minimal HS256 JWT implementation
 *
 * Uses only the Node.js built-in `node:crypto` module (HMAC-SHA256).
 * No third-party JWT library is required, keeping the supply-chain
 * surface minimal.
 *
 * Limitations (by design):
 * - Only HS256 is supported.
 * - Only the `sub`, `iat`, and `exp` standard claims are produced.
 * - Verification rejects expired tokens and tokens with a wrong signature.
 * - No key rotation, no key ID (`kid`), no JWK support.
 *
 * Security:
 * - Signature verification uses `crypto.timingSafeEqual` to prevent
 *   timing-oracle attacks on the HMAC comparison.
 * - The secret must be ≥ 32 bytes (UTF-8 encoded) to meet NIST SP 800-107
 *   minimum key-length guidance for HMAC-SHA256.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { InvalidJwtError } from './jwt-errors';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Fixed JWT header for HS256. Pre-encoded to avoid repeated computation. */
const HEADER_B64 = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));

/** Minimum secret length in bytes (UTF-8 encoded). */
const MIN_SECRET_BYTES = 32;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Claims embedded in every JWT issued by this module.
 */
export interface ZkpJwtPayload {
  /** Subject — the authenticated `userId`. */
  sub: string;
  /** Issued-at (Unix seconds). */
  iat: number;
  /** Expiry (Unix seconds). */
  exp: number;
}

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

/**
 * Sign a JWT containing `{ sub, iat, exp }` claims using HS256.
 *
 * @param userId             The authenticated user identifier (becomes `sub`).
 * @param secret             HMAC key string. Must produce ≥ 32 UTF-8 bytes.
 * @param expiresInSeconds   Token lifetime in seconds. Default: 3600.
 * @returns                  A compact JWT string `header.payload.signature`.
 * @throws TypeError         When `secret` encodes to fewer than 32 bytes.
 */
export function signJwt(userId: string, secret: string, expiresInSeconds = 3_600): string {
  assertSecretLength(secret);

  const iat = Math.floor(Date.now() / 1_000);
  const payload: ZkpJwtPayload = { sub: userId, iat, exp: iat + expiresInSeconds };

  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${HEADER_B64}.${payloadB64}`;
  const sig = hmacSha256B64(signingInput, secret);

  return `${signingInput}.${sig}`;
}

/**
 * Verify and decode a JWT produced by `signJwt`.
 *
 * Rejects tokens with:
 * - Wrong number of parts.
 * - Invalid base64url encoding.
 * - Non-HS256 algorithm header.
 * - Signature mismatch (constant-time comparison).
 * - `exp` in the past.
 *
 * @param token  Compact JWT string.
 * @param secret HMAC key string. Must match the key used during signing.
 * @returns      Decoded, verified payload.
 * @throws InvalidJwtError When the token is structurally invalid, expired,
 *                         or has a bad signature.
 */
export function verifyJwt(token: string, secret: string): ZkpJwtPayload {
  assertSecretLength(secret);

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new InvalidJwtError('Malformed token: expected 3 dot-separated parts');
  }

  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  // Verify header claims alg === HS256
  const header = safeJsonParse(base64UrlDecode(headerB64));
  if (
    header === null ||
    typeof header !== 'object' ||
    (header as Record<string, unknown>)['alg'] !== 'HS256'
  ) {
    throw new InvalidJwtError('Malformed token: invalid header');
  }

  // Re-compute expected signature and compare constant-time
  const signingInput = `${headerB64}.${payloadB64}`;
  const expectedSig = hmacSha256B64(signingInput, secret);

  if (!timingSafeEqualStrings(sigB64, expectedSig)) {
    throw new InvalidJwtError('Invalid signature');
  }

  // Decode and validate payload
  const payload = safeJsonParse(base64UrlDecode(payloadB64));
  if (
    payload === null ||
    typeof payload !== 'object' ||
    typeof (payload as Record<string, unknown>)['sub'] !== 'string' ||
    typeof (payload as Record<string, unknown>)['iat'] !== 'number' ||
    typeof (payload as Record<string, unknown>)['exp'] !== 'number'
  ) {
    throw new InvalidJwtError('Malformed token: invalid payload shape');
  }

  const typed = payload as ZkpJwtPayload;
  if (Math.floor(Date.now() / 1_000) >= typed.exp) {
    throw new InvalidJwtError('Token has expired');
  }

  return typed;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Compute HMAC-SHA256 and return base64url-encoded result.
 *
 * @param data   Input string.
 * @param secret HMAC key string.
 */
function hmacSha256B64(data: string, secret: string): string {
  return createHmac('sha256', secret).update(data).digest('base64url');
}

/**
 * Encode a UTF-8 string as base64url (no padding).
 */
function base64UrlEncode(data: string): string {
  return Buffer.from(data, 'utf8').toString('base64url');
}

/**
 * Decode a base64url string back to UTF-8.
 */
function base64UrlDecode(encoded: string): string {
  return Buffer.from(encoded, 'base64url').toString('utf8');
}

/**
 * Attempt JSON.parse without throwing.
 * Returns `null` on any parse error.
 */
function safeJsonParse(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
}

/**
 * Constant-time string equality using `crypto.timingSafeEqual`.
 *
 * Compares the UTF-8 byte representations so timing is not influenced by
 * early-exit branch evaluation.
 */
function timingSafeEqualStrings(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  // timingSafeEqual requires identical lengths; if lengths differ the strings
  // are definitely not equal — but we still run the comparison on a zeroed
  // buffer to avoid a trivial length-oracle.
  if (bufA.length !== bufB.length) {
    // Compare something of equal length so the function takes a consistent
    // time path. The result is discarded; we return false.
    const dummy = Buffer.alloc(bufA.length);
    timingSafeEqual(bufA, dummy);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

/**
 * Assert that the secret encodes to at least `MIN_SECRET_BYTES` bytes in UTF-8.
 *
 * @throws TypeError When the secret is too short.
 */
function assertSecretLength(secret: string): void {
  const bytes = Buffer.byteLength(secret, 'utf8');
  if (bytes < MIN_SECRET_BYTES) {
    throw new TypeError(
      `JWT secret must be at least ${MIN_SECRET_BYTES} bytes (UTF-8); got ${bytes}`,
    );
  }
}
