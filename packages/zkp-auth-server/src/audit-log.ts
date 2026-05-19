/**
 * @zkp-auth/server — security audit logging.
 *
 * This module keeps audit policy separate from auth decisions:
 * - usernames are hashed with SHA-256 before leaving this module
 * - records are structured JSON so downstream sinks stay machine-readable
 * - sink failures are swallowed after a best-effort fallback so logging
 *   cannot become an authentication outage
 */

import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type AuditSeverity = 'info' | 'warn' | 'critical';

export interface AuditTimestamp {
  readonly timestamp: string;
  readonly timestampMs: number;
}

export interface AuditBaseRecord extends AuditTimestamp {
  readonly ip: string;
  readonly usernameHash: string;
}

export interface RegistrationAuditRecord extends AuditBaseRecord {
  readonly event: 'registration_attempt';
  readonly severity: 'info' | 'warn';
  readonly success: boolean;
  readonly reason?: string;
}

export interface KeyOverwriteAuditRecord extends AuditBaseRecord {
  readonly event: 'key_overwrite_attempt';
  readonly severity: 'critical';
  readonly success: boolean;
  readonly reason?: string;
}

export type AuditRecord = RegistrationAuditRecord | KeyOverwriteAuditRecord;

export interface RegistrationAttemptInput {
  readonly userId: string;
  readonly ip: string;
  readonly success: boolean;
  readonly reason?: string;
  readonly timestamp?: number | Date;
}

export interface KeyOverwriteAttemptInput {
  readonly userId: string;
  readonly ip: string;
  readonly success: boolean;
  readonly reason?: string;
  readonly timestamp?: number | Date;
}

export interface AuditSink {
  write(record: AuditRecord): void | Promise<void>;
}

export interface AuditLogger {
  logRegistrationAttempt(input: RegistrationAttemptInput): Promise<void>;
  logKeyOverwriteAttempt(input: KeyOverwriteAttemptInput): Promise<void>;
}

// ---------------------------------------------------------------------------
// Hashing / timestamps
// ---------------------------------------------------------------------------

/**
 * Hash a username before it is written to any audit sink.
 *
 * This is intentionally one-way so logs can support investigations without
 * persisting plaintext identifiers.
 */
export function hashUsername(userId: string): string {
  return createHash('sha256').update(userId, 'utf8').digest('hex');
}

function toTimestamp(input?: number | Date): AuditTimestamp {
  const timestampMs =
    input instanceof Date ? input.getTime() : typeof input === 'number' ? input : Date.now();
  const safeTimestampMs = Number.isFinite(timestampMs) ? timestampMs : Date.now();
  return {
    timestampMs: safeTimestampMs,
    timestamp: new Date(safeTimestampMs).toISOString(),
  };
}

function normalizeIp(ip: string): string {
  const trimmed = ip.trim();
  return trimmed.length > 0 ? trimmed : 'unknown';
}

// ---------------------------------------------------------------------------
// Sink implementations
// ---------------------------------------------------------------------------

class StderrJsonAuditSink implements AuditSink {
  write(record: AuditRecord): void {
    process.stderr.write(`${JSON.stringify(record)}\n`);
  }
}

function safeFallbackWrite(record: AuditRecord): void {
  try {
    process.stderr.write(`${JSON.stringify({ ...record, fallback: true })}\n`);
  } catch {
    // Intentionally swallow: audit logging must not fail closed and should not
    // turn a sink outage into an auth outage.
  }
}

async function emitRecord(sink: AuditSink, record: AuditRecord): Promise<void> {
  try {
    await sink.write(record);
  } catch {
    safeFallbackWrite(record);
  }
}

// ---------------------------------------------------------------------------
// Record builders
// ---------------------------------------------------------------------------

function buildRegistrationRecord(input: RegistrationAttemptInput): RegistrationAuditRecord {
  return {
    event: 'registration_attempt',
    severity: input.success ? 'info' : 'warn',
    success: input.success,
    reason: input.reason,
    ip: normalizeIp(input.ip),
    usernameHash: hashUsername(input.userId),
    ...toTimestamp(input.timestamp),
  };
}

function buildKeyOverwriteRecord(input: KeyOverwriteAttemptInput): KeyOverwriteAuditRecord {
  return {
    event: 'key_overwrite_attempt',
    severity: 'critical',
    success: input.success,
    reason: input.reason,
    ip: normalizeIp(input.ip),
    usernameHash: hashUsername(input.userId),
    ...toTimestamp(input.timestamp),
  };
}

// ---------------------------------------------------------------------------
// Public logger
// ---------------------------------------------------------------------------

export function createAuditLogger(sink: AuditSink = new StderrJsonAuditSink()): AuditLogger {
  return {
    async logRegistrationAttempt(input: RegistrationAttemptInput): Promise<void> {
      await emitRecord(sink, buildRegistrationRecord(input));
    },

    async logKeyOverwriteAttempt(input: KeyOverwriteAttemptInput): Promise<void> {
      await emitRecord(sink, buildKeyOverwriteRecord(input));
    },
  };
}

export const defaultAuditLogger = createAuditLogger();

export async function logRegistrationAttempt(
  input: RegistrationAttemptInput,
  logger: AuditLogger = defaultAuditLogger,
): Promise<void> {
  await logger.logRegistrationAttempt(input);
}

export async function logKeyOverwriteAttempt(
  input: KeyOverwriteAttemptInput,
  logger: AuditLogger = defaultAuditLogger,
): Promise<void> {
  await logger.logKeyOverwriteAttempt(input);
}
