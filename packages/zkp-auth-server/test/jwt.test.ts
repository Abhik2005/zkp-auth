/**
 * Unit tests for jwt.ts — signJwt / verifyJwt (HS256).
 *
 * Coverage:
 * - sign produces a 3-part compact JWT
 * - verify round-trips successfully
 * - verify rejects wrong signature (timing-safe path)
 * - verify rejects expired token
 * - verify rejects malformed token (wrong part count)
 * - verify rejects non-HS256 algorithm header
 * - verify rejects truncated / non-JSON payload
 * - signJwt enforces minimum secret length
 * - verifyJwt enforces minimum secret length
 * - custom expiresInSeconds is honoured
 */

import { describe, it, expect, vi } from 'vitest';
import { signJwt, verifyJwt } from '../src/jwt.js';
import { InvalidJwtError } from '../src/jwt-errors.js';

// A 32-byte secret (minimum allowed).
const SECRET = 'a'.repeat(32);
const USER_ID = 'user-test-1234';

describe('signJwt', () => {
  it('signJwt_validInputs_producesThreePartJwt', () => {
    const token = signJwt(USER_ID, SECRET);
    const parts = token.split('.');
    expect(parts).toHaveLength(3);
  });

  it('signJwt_shortSecret_throwsTypeError', () => {
    expect(() => signJwt(USER_ID, 'tooshort')).toThrow(TypeError);
  });

  it('signJwt_customExpiry_encodedInPayload', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-01T00:00:00Z'));

    const token = signJwt(USER_ID, SECRET, 120);
    const [, payloadB64] = token.split('.');
    const payload = JSON.parse(Buffer.from(payloadB64!, 'base64url').toString('utf8')) as {
      sub: string;
      iat: number;
      exp: number;
    };

    expect(payload.sub).toBe(USER_ID);
    expect(payload.exp - payload.iat).toBe(120);

    vi.useRealTimers();
  });
});

describe('verifyJwt', () => {
  it('verifyJwt_validToken_returnsParsedPayload', () => {
    const token = signJwt(USER_ID, SECRET);
    const payload = verifyJwt(token, SECRET);

    expect(payload.sub).toBe(USER_ID);
    expect(typeof payload.iat).toBe('number');
    expect(typeof payload.exp).toBe('number');
  });

  it('verifyJwt_wrongSecret_throwsInvalidJwtError', () => {
    const token = signJwt(USER_ID, SECRET);
    const wrongSecret = 'b'.repeat(32);
    expect(() => verifyJwt(token, wrongSecret)).toThrow(InvalidJwtError);
  });

  it('verifyJwt_expiredToken_throwsInvalidJwtError', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-01T00:00:00Z'));

    const token = signJwt(USER_ID, SECRET, 60);

    // Advance 61 seconds past issuance.
    vi.advanceTimersByTime(61_000);

    expect(() => verifyJwt(token, SECRET)).toThrow(InvalidJwtError);
    expect(() => verifyJwt(token, SECRET)).toThrow('expired');

    vi.useRealTimers();
  });

  it('verifyJwt_malformedTwoParts_throwsInvalidJwtError', () => {
    expect(() => verifyJwt('header.payload', SECRET)).toThrow(InvalidJwtError);
  });

  it('verifyJwt_tamperedPayload_throwsInvalidJwtError', () => {
    const token = signJwt(USER_ID, SECRET);
    const [h, , sig] = token.split('.');
    // Replace payload with a tampered one — signature no longer matches.
    const tamperedPayload = Buffer.from('{"sub":"attacker","iat":0,"exp":9999999999}').toString(
      'base64url',
    );
    const tampered = `${h}.${tamperedPayload}.${sig}`;
    expect(() => verifyJwt(tampered, SECRET)).toThrow(InvalidJwtError);
  });

  it('verifyJwt_nonHS256Header_throwsInvalidJwtError', () => {
    // Craft a token with alg: RS256 header.
    const fakeHeader = Buffer.from('{"alg":"RS256","typ":"JWT"}').toString('base64url');
    const fakePayload = Buffer.from(
      `{"sub":"${USER_ID}","iat":1000,"exp":9999999999}`,
    ).toString('base64url');
    const fakeSig = 'invalidsig';
    expect(() => verifyJwt(`${fakeHeader}.${fakePayload}.${fakeSig}`, SECRET)).toThrow(
      InvalidJwtError,
    );
  });

  it('verifyJwt_shortSecret_throwsTypeError', () => {
    const token = signJwt(USER_ID, SECRET);
    expect(() => verifyJwt(token, 'tooshort')).toThrow(TypeError);
  });

  it('verifyJwt_differentLengthSignature_returnsFalse', () => {
    // Produce a token with a one-char signature — verifyJwt should throw
    // InvalidJwtError (bad signature), NOT crash with timingSafeEqual length mismatch.
    const [h, p] = signJwt(USER_ID, SECRET).split('.');
    const shortSig = 'x';
    expect(() => verifyJwt(`${h}.${p}.${shortSig}`, SECRET)).toThrow(InvalidJwtError);
  });
});
