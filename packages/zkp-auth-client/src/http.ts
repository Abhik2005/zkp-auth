// @zkp-auth/client — typed fetch transport layer
//
// Provides three typed wrappers — `postRegister`, `postChallenge`,
// `postVerify` — that speak the exact wire protocol defined by
// @zkp-auth/server's Express middleware:
//
//   POST /auth/register  { userId, publicKeyHex }          → 201
//   POST /auth/challenge { userId }                        → 200
//   POST /auth/verify    { userId, proofHex }              → 200 (downstream)
//
// Each wrapper:
//   1. Sends `Content-Type: application/json` with the request body.
//   2. Throws `ZkpNetworkError` when `fetch()` itself rejects.
//   3. Parses the JSON body and throws a typed `ZkpServerError` for any
//      non-2xx response, preserving `httpStatus` and `serverCode`.
//   4. Returns the parsed success body on a 2xx response.
//
// No business logic (key generation, proof computation) lives here.
// Callers pass pre-encoded hex strings; this layer only handles HTTP.

import { ZkpNetworkError, ZkpServerError } from './errors.js';

// ── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Shape of the server's error envelope for non-2xx responses.
 * Mirrors @zkp-auth/server's `ErrorResponseBody`.
 */
interface ServerErrorEnvelope {
  error: {
    code: string;
    message: string;
  };
}

function isServerErrorEnvelope(value: unknown): value is ServerErrorEnvelope {
  return (
    typeof value === 'object' &&
    value !== null &&
    'error' in value &&
    typeof (value as Record<string, unknown>)['error'] === 'object' &&
    (value as Record<string, unknown>)['error'] !== null &&
    typeof ((value as ServerErrorEnvelope).error).code === 'string' &&
    typeof ((value as ServerErrorEnvelope).error).message === 'string'
  );
}

/**
 * Execute a POST request with a JSON body.
 *
 * @param url     Absolute URL to POST to.
 * @param body    JSON-serialisable request body.
 * @returns       Parsed JSON response body on success (2xx).
 * @throws ZkpNetworkError   When `fetch()` itself rejects.
 * @throws ZkpServerError    On any non-2xx response.
 */
async function postJson(url: string, body: unknown): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      credentials: "include"
    });
  } catch (cause: unknown) {
    throw new ZkpNetworkError(
      `Network error posting to ${url}: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }

  // Parse the response body regardless of status so we can include the
  // server's error code in the thrown ZkpServerError.
  let parsed: unknown;
  try {
    parsed = await response.json() as unknown;
  } catch {
    // Body is not valid JSON — still surface the HTTP failure if non-2xx.
    parsed = undefined;
  }

  if (!response.ok) {
    const serverCode = isServerErrorEnvelope(parsed) ? parsed.error.code : undefined;
    const serverMsg = isServerErrorEnvelope(parsed) ? parsed.error.message : `HTTP ${response.status.toString()}`;
    // The clientCode is resolved by the caller wrapping postJson.
    throw new ZkpServerError('SERVER_ERROR', serverMsg, response.status, serverCode);
  }

  return parsed;
}

// ── Wire shapes ───────────────────────────────────────────────────────────────

/** Body sent to `POST /auth/register`. */
interface RegisterRequestBody {
  userId: string;
  publicKeyHex: string;
}

/** Body sent to `POST /auth/challenge`. */
interface ChallengeRequestBody {
  userId: string;
}

/** Body sent to `POST /auth/verify`. */
interface VerifyRequestBody {
  userId: string;
  proofHex: string;
}

// ── Success response shapes (mirrors @zkp-auth/server's handler returns) ─────

/** Server response on successful `POST /auth/register`. */
export interface RegisterResult {
  status: 'registered';
  userId: string;
}

/** Server response on successful `POST /auth/challenge`. */
export interface ChallengeResult {
  status: 'challenge_issued';
  /** Hex-encoded 32-byte challenge. The client decodes this to a Uint8Array. */
  challengeHex: string;
  /** Challenge TTL in milliseconds (informational). */
  expiresInMs: number;
}

/** Server response on successful `POST /auth/verify`. */
export interface VerifyResult {
  /**
   * Signed HS256 JWT returned by the application route handler.
   * Optional: cookie-based servers omit this and set an HttpOnly cookie instead.
   */
  token?: string;
}

// ── Type guards for success bodies ────────────────────────────────────────────

function isRegisterResult(v: unknown): v is RegisterResult {
  return (
    typeof v === 'object' &&
    v !== null &&
    (v as RegisterResult).status === 'registered' &&
    typeof (v as RegisterResult).userId === 'string'
  );
}

function isChallengeResult(v: unknown): v is ChallengeResult {
  return (
    typeof v === 'object' &&
    v !== null &&
    (v as ChallengeResult).status === 'challenge_issued' &&
    typeof (v as ChallengeResult).challengeHex === 'string' &&
    typeof (v as ChallengeResult).expiresInMs === 'number'
  );
}

function isVerifyResult(v: unknown): v is VerifyResult {
  // Accept both token-in-body (legacy) and cookie-based (no token) server responses.
  // The only hard requirement is that the server returned a non-null object —
  // the token field is optional when the JWT is delivered via HttpOnly cookie.
  return typeof v === 'object' && v !== null;
}

// ── Public transport functions ────────────────────────────────────────────────

/**
 * POST `{ userId, publicKeyHex }` to `baseUrl + '/auth/register'`.
 *
 * @param baseUrl      Server base URL (no trailing slash), e.g. `'https://api.example.com'`.
 * @param userId       User identifier string.
 * @param publicKeyHex 64-character lowercase hex string (32-byte Ed25519 public key).
 *
 * @returns `RegisterResult` on HTTP 201.
 * @throws ZkpNetworkError               On fetch rejection.
 * @throws ZkpServerError('REGISTER_FAILED') On non-2xx response.
 * @throws ZkpServerError('SERVER_ERROR')    On malformed success body.
 */
export async function postRegister(
  baseUrl: string,
  userId: string,
  publicKeyHex: string,
): Promise<RegisterResult> {
  const body: RegisterRequestBody = { userId, publicKeyHex };
  let raw: unknown;
  try {
    raw = await postJson(`${baseUrl}/auth/register`, body);
  } catch (e: unknown) {
    if (e instanceof ZkpServerError) {
      // Re-throw with the domain-specific client code.
      throw new ZkpServerError(
        'REGISTER_FAILED',
        e.message,
        e.httpStatus,
        e.serverCode,
      );
    }
    throw e; // ZkpNetworkError propagates unchanged.
  }

  if (!isRegisterResult(raw)) {
    throw new ZkpServerError(
      'REGISTER_FAILED',
      'Server returned an unexpected body for /auth/register',
      200,
    );
  }
  return raw;
}

/**
 * POST `{ userId }` to `baseUrl + '/auth/challenge'` to request a
 * server-issued 32-byte challenge.
 *
 * @param baseUrl Server base URL (no trailing slash).
 * @param userId  User identifier string.
 *
 * @returns `ChallengeResult` containing `challengeHex` and `expiresInMs`.
 * @throws ZkpNetworkError                 On fetch rejection.
 * @throws ZkpServerError('CHALLENGE_FAILED') On non-2xx response.
 * @throws ZkpServerError('SERVER_ERROR')     On malformed success body.
 */
export async function postChallenge(
  baseUrl: string,
  userId: string,
): Promise<ChallengeResult> {
  const body: ChallengeRequestBody = { userId };
  let raw: unknown;
  try {
    raw = await postJson(`${baseUrl}/auth/challenge`, body);
  } catch (e: unknown) {
    if (e instanceof ZkpServerError) {
      throw new ZkpServerError(
        'CHALLENGE_FAILED',
        e.message,
        e.httpStatus,
        e.serverCode,
      );
    }
    throw e;
  }

  if (!isChallengeResult(raw)) {
    throw new ZkpServerError(
      'CHALLENGE_FAILED',
      'Server returned an unexpected body for /auth/challenge',
      200,
    );
  }
  return raw;
}

/**
 * POST `{ userId, proofHex }` to `baseUrl + '/auth/verify'` and return the
 * JWT issued by the application route handler.
 *
 * The server middleware sets `res.locals.zkpToken` and calls `next()`.
 * The downstream route handler is responsible for returning the token in the
 * response body; this client expects it at `response.token`.
 *
 * @param baseUrl  Server base URL (no trailing slash).
 * @param userId   User identifier string.
 * @param proofHex 128-character lowercase hex string (64-byte proof).
 *
 * @returns `VerifyResult` containing the signed JWT token.
 * @throws ZkpNetworkError                On fetch rejection.
 * @throws ZkpServerError('PROOF_REJECTED')  On 4xx response (proof invalid,
 *   challenge not found, etc.).
 * @throws ZkpServerError('SERVER_ERROR')    On 5xx or malformed success body.
 */
export async function postVerify(
  baseUrl: string,
  userId: string,
  proofHex: string,
): Promise<VerifyResult> {
  const body: VerifyRequestBody = { userId, proofHex };
  let raw: unknown;
  try {
    raw = await postJson(`${baseUrl}/auth/verify`, body);
  } catch (e: unknown) {
    if (e instanceof ZkpServerError) {
      // 4xx errors from the verify endpoint indicate proof/challenge failures.
      const clientCode =
        e.httpStatus >= 400 && e.httpStatus < 500 ? 'PROOF_REJECTED' : 'SERVER_ERROR';
      throw new ZkpServerError(clientCode, e.message, e.httpStatus, e.serverCode);
    }
    throw e;
  }

  if (!isVerifyResult(raw)) {
    throw new ZkpServerError(
      'SERVER_ERROR',
      'Server returned an unexpected body for /auth/verify (expected { token: string })',
      200,
    );
  }
  return raw;
}

// ── Encoding helpers (exported for use in client.ts) ─────────────────────────

/**
 * Encode a `Uint8Array` as a lowercase hex string.
 * Used to convert `publicKey` → `publicKeyHex` and `proof` → `proofHex`.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Decode a lowercase hex string into a `Uint8Array`.
 * Used to convert the server's `challengeHex` → `Uint8Array` for proof input.
 *
 * @throws ZkpServerError('SERVER_ERROR') when `hex` has an odd length or
 *   contains non-hex characters — indicating a malformed server response.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new ZkpServerError(
      'SERVER_ERROR',
      `Server returned an odd-length hex string: length=${hex.length.toString()}`,
      200,
    );
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new ZkpServerError(
        'SERVER_ERROR',
        `Server returned a non-hex character in challengeHex at offset ${(i * 2).toString()}`,
        200,
      );
    }
    bytes[i] = byte;
  }
  return bytes;
}
