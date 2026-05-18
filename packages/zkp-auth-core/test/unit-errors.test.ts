// Unit tests for the typed error classes exported by `../src/errors.ts`.
//
// Validates: Requirements 7.1, 7.2, 7.4, 7.5
//
// These tests lock the public-API contract of `InvalidInputError`,
// `RandomnessError`, and `CryptoError` so callers can pattern-match on
// `.name` and `.code` and recover the underlying failure via `.cause`.

import { describe, it, expect } from 'vitest';
import {
  InvalidInputError,
  RandomnessError,
  CryptoError,
  type ErrorCode,
} from '../src/errors';

// The complete `ErrorCode` union as declared in `src/errors.ts`. Listing it
// explicitly here lets us exercise every member through `InvalidInputError`
// and lets the type system catch a future addition that drifts away from
// what the tests cover (the assignment `readonly ErrorCode[]` is structural,
// so adding a new code without updating this list still type-checks — but
// adding a new code is a breaking change to the public API per the JSDoc
// in `errors.ts`, and the maintainer is expected to update this list).
const ALL_ERROR_CODES: readonly ErrorCode[] = [
  'INVALID_PRIVATE_KEY',
  'INVALID_PUBLIC_KEY',
  'INVALID_CHALLENGE',
  'INVALID_PROOF',
  'INVALID_PASSWORD',
  'INVALID_SESSION_ID',
  'RNG_FAILURE',
  'CURVE_ERROR',
];

describe('InvalidInputError', () => {
  it('is an instance of Error', () => {
    const err = new InvalidInputError('INVALID_PRIVATE_KEY', 'bad key');
    expect(err).toBeInstanceOf(Error);
  });

  it('is an instance of InvalidInputError', () => {
    const err = new InvalidInputError('INVALID_PRIVATE_KEY', 'bad key');
    expect(err).toBeInstanceOf(InvalidInputError);
  });

  it('sets .name to the literal "InvalidInputError"', () => {
    const err = new InvalidInputError('INVALID_CHALLENGE', 'bad challenge');
    expect(err.name).toBe('InvalidInputError');
  });

  it('round-trips .code from the first constructor argument', () => {
    const err = new InvalidInputError('INVALID_PROOF', 'bad proof');
    expect(err.code).toBe('INVALID_PROOF');
  });

  it('sets .message from the second constructor argument', () => {
    const err = new InvalidInputError('INVALID_PUBLIC_KEY', 'pk decode failed');
    expect(err.message).toBe('pk decode failed');
  });

  it('does not attach a .cause property (this class accepts no cause)', () => {
    const err = new InvalidInputError('INVALID_SESSION_ID', 'oversize sessionId');
    expect('cause' in err).toBe(false);
    expect(err.cause).toBeUndefined();
  });

  it('accepts every member of the ErrorCode union and round-trips it via .code', () => {
    for (const code of ALL_ERROR_CODES) {
      const err = new InvalidInputError(code, `code=${code}`);
      expect(err.code).toBe(code);
      // .name is fixed regardless of which code was passed
      expect(err.name).toBe('InvalidInputError');
    }
  });
});

describe('RandomnessError', () => {
  it('is an instance of Error', () => {
    const err = new RandomnessError('CSPRNG failure');
    expect(err).toBeInstanceOf(Error);
  });

  it('is an instance of RandomnessError', () => {
    const err = new RandomnessError('CSPRNG failure');
    expect(err).toBeInstanceOf(RandomnessError);
  });

  it('sets .name to the literal "RandomnessError"', () => {
    const err = new RandomnessError('CSPRNG failure');
    expect(err.name).toBe('RandomnessError');
  });

  it('fixes .code to the literal "RNG_FAILURE" when no options are passed', () => {
    const err = new RandomnessError('CSPRNG failure');
    expect(err.code).toBe('RNG_FAILURE');
  });

  it('still fixes .code to "RNG_FAILURE" when options.cause is provided', () => {
    const err = new RandomnessError('CSPRNG failure', { cause: new Error('x') });
    expect(err.code).toBe('RNG_FAILURE');
  });

  it('sets .message from the first constructor argument', () => {
    const err = new RandomnessError('CSPRNG returned short read');
    expect(err.message).toBe('CSPRNG returned short read');
  });

  it('omits .cause when no options object is passed', () => {
    const err = new RandomnessError('CSPRNG failure');
    expect('cause' in err).toBe(false);
    expect(err.cause).toBeUndefined();
  });

  it('omits .cause when options is passed without a .cause field', () => {
    const err = new RandomnessError('CSPRNG failure', {});
    expect('cause' in err).toBe(false);
    expect(err.cause).toBeUndefined();
  });

  it('omits .cause when options.cause is explicitly undefined', () => {
    const err = new RandomnessError('CSPRNG failure', { cause: undefined });
    expect('cause' in err).toBe(false);
    expect(err.cause).toBeUndefined();
  });

  it('round-trips an Error .cause when options.cause is provided', () => {
    const underlying = new Error('underlying CSPRNG throw');
    const err = new RandomnessError('CSPRNG failure', { cause: underlying });
    expect(err.cause).toBe(underlying);
  });

  it('round-trips a non-Error .cause (the field is typed as unknown)', () => {
    const cause: unknown = { reason: 'short-read', bytesReturned: 17 };
    const err = new RandomnessError('CSPRNG failure', { cause });
    expect(err.cause).toBe(cause);
  });
});

describe('CryptoError', () => {
  it('is an instance of Error', () => {
    const err = new CryptoError('curve op failed');
    expect(err).toBeInstanceOf(Error);
  });

  it('is an instance of CryptoError', () => {
    const err = new CryptoError('curve op failed');
    expect(err).toBeInstanceOf(CryptoError);
  });

  it('sets .name to the literal "CryptoError"', () => {
    const err = new CryptoError('curve op failed');
    expect(err.name).toBe('CryptoError');
  });

  it('fixes .code to the literal "CURVE_ERROR" when no options are passed', () => {
    const err = new CryptoError('curve op failed');
    expect(err.code).toBe('CURVE_ERROR');
  });

  it('still fixes .code to "CURVE_ERROR" when options.cause is provided', () => {
    const err = new CryptoError('curve op failed', { cause: new Error('x') });
    expect(err.code).toBe('CURVE_ERROR');
  });

  it('sets .message from the first constructor argument', () => {
    const err = new CryptoError('point decoding failed');
    expect(err.message).toBe('point decoding failed');
  });

  it('omits .cause when no options object is passed', () => {
    const err = new CryptoError('curve op failed');
    expect('cause' in err).toBe(false);
    expect(err.cause).toBeUndefined();
  });

  it('omits .cause when options is passed without a .cause field', () => {
    const err = new CryptoError('curve op failed', {});
    expect('cause' in err).toBe(false);
    expect(err.cause).toBeUndefined();
  });

  it('omits .cause when options.cause is explicitly undefined', () => {
    const err = new CryptoError('curve op failed', { cause: undefined });
    expect('cause' in err).toBe(false);
    expect(err.cause).toBeUndefined();
  });

  it('round-trips an Error .cause when options.cause is provided', () => {
    const underlying = new Error('noble point-decode failure');
    const err = new CryptoError('curve op failed', { cause: underlying });
    expect(err.cause).toBe(underlying);
  });

  it('round-trips a non-Error .cause (the field is typed as unknown)', () => {
    const cause: unknown = 'string-shaped underlying error';
    const err = new CryptoError('curve op failed', { cause });
    expect(err.cause).toBe(cause);
  });
});
