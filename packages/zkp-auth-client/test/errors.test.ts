// tests/errors.test.ts — unit tests for @zkp-auth/client error classes
//
// Tier: Unit
// Covers: ZkpClientError, ZkpCryptoError, ZkpNetworkError, ZkpServerError
// Pattern: Arrange / Act / Assert

import { describe, it, expect } from 'vitest';
import {
  ZkpClientError,
  ZkpCryptoError,
  ZkpNetworkError,
  ZkpServerError,
} from '../src/errors.js';
import type { ClientErrorCode } from '../src/errors.js';

// ── ZkpClientError ────────────────────────────────────────────────────────────

describe('ZkpClientError', () => {
  it('stores code and message correctly', () => {
    const err = new ZkpClientError('RNG_FAILURE', 'test message');
    expect(err.code).toBe('RNG_FAILURE' satisfies ClientErrorCode);
    expect(err.message).toBe('test message');
    expect(err.name).toBe('ZkpClientError');
  });

  it('is an instance of Error', () => {
    const err = new ZkpClientError('CURVE_ERROR', 'x');
    expect(err).toBeInstanceOf(Error);
  });

  it('instanceof works after construction (prototype chain restored)', () => {
    const err = new ZkpClientError('NETWORK_ERROR', 'x');
    expect(err).toBeInstanceOf(ZkpClientError);
  });
});

// ── ZkpCryptoError ────────────────────────────────────────────────────────────

describe('ZkpCryptoError', () => {
  it('stores code and message', () => {
    const err = new ZkpCryptoError('RNG_FAILURE', 'rng failed');
    expect(err.code).toBe('RNG_FAILURE');
    expect(err.message).toBe('rng failed');
    expect(err.name).toBe('ZkpCryptoError');
  });

  it('is instanceof ZkpClientError and Error', () => {
    const err = new ZkpCryptoError('CURVE_ERROR', 'c');
    expect(err).toBeInstanceOf(ZkpCryptoError);
    expect(err).toBeInstanceOf(ZkpClientError);
    expect(err).toBeInstanceOf(Error);
  });

  it('attaches cause when provided', () => {
    const underlying = new Error('underlying');
    const err = new ZkpCryptoError('CURVE_ERROR', 'wrapped', { cause: underlying });
    expect((err as { cause?: unknown }).cause).toBe(underlying);
  });

  it('does not attach cause when options are absent', () => {
    const err = new ZkpCryptoError('INVALID_USERNAME', 'no cause');
    expect((err as { cause?: unknown }).cause).toBeUndefined();
  });

  it('accepts all crypto-layer codes', () => {
    const codes = ['INVALID_USERNAME', 'INVALID_PASSWORD', 'RNG_FAILURE', 'CURVE_ERROR'] as const;
    for (const code of codes) {
      const err = new ZkpCryptoError(code, 'test');
      expect(err.code).toBe(code);
    }
  });
});

// ── ZkpNetworkError ───────────────────────────────────────────────────────────

describe('ZkpNetworkError', () => {
  it('always has code NETWORK_ERROR', () => {
    const err = new ZkpNetworkError('offline');
    expect(err.code).toBe('NETWORK_ERROR');
    expect(err.name).toBe('ZkpNetworkError');
  });

  it('is instanceof ZkpClientError and Error', () => {
    const err = new ZkpNetworkError('x');
    expect(err).toBeInstanceOf(ZkpNetworkError);
    expect(err).toBeInstanceOf(ZkpClientError);
    expect(err).toBeInstanceOf(Error);
  });

  it('attaches cause when provided', () => {
    const cause = new TypeError('fetch failed');
    const err = new ZkpNetworkError('net error', { cause });
    expect((err as { cause?: unknown }).cause).toBe(cause);
  });
});

// ── ZkpServerError ────────────────────────────────────────────────────────────

describe('ZkpServerError', () => {
  it('stores code, message, httpStatus, and serverCode', () => {
    const err = new ZkpServerError('PROOF_REJECTED', 'bad proof', 400, 'PROOF_INVALID');
    expect(err.code).toBe('PROOF_REJECTED');
    expect(err.message).toBe('bad proof');
    expect(err.httpStatus).toBe(400);
    expect(err.serverCode).toBe('PROOF_INVALID');
    expect(err.name).toBe('ZkpServerError');
  });

  it('serverCode is undefined when not provided', () => {
    const err = new ZkpServerError('SERVER_ERROR', 'oops', 500);
    expect(err.serverCode).toBeUndefined();
  });

  it('is instanceof ZkpClientError and Error', () => {
    const err = new ZkpServerError('REGISTER_FAILED', 'x', 409);
    expect(err).toBeInstanceOf(ZkpServerError);
    expect(err).toBeInstanceOf(ZkpClientError);
    expect(err).toBeInstanceOf(Error);
  });

  it('accepts all server-layer codes', () => {
    const cases = [
      ['REGISTER_FAILED', 409],
      ['CHALLENGE_FAILED', 404],
      ['PROOF_REJECTED', 401],
      ['SERVER_ERROR', 500],
    ] as const;
    for (const [code, status] of cases) {
      const err = new ZkpServerError(code, 'test', status);
      expect(err.code).toBe(code);
      expect(err.httpStatus).toBe(status);
    }
  });
});
