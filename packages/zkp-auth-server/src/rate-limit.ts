/**
 * @zkp-auth/server — small in-memory auth rate limiter
 *
 * Provides a conservative default limiter for auth endpoints. The store is
 * process-local; horizontally scaled deployments should use an external
 * limiter through the existing `rateLimitHook` option or replace this helper
 * with a Redis/database-backed implementation.
 */

import type { Request } from 'express';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const HOUR_MS = 60 * 60 * 1_000;
const DAY_MS = 24 * HOUR_MS;

const DEFAULT_REGISTER_MAX_PER_HOUR = 5;
const DEFAULT_REGISTER_MAX_PER_DAY = 3;
const DEFAULT_AUTH_MAX_PER_HOUR = 60;
const DEFAULT_AUTH_MAX_PER_DAY = 300;
const DEFAULT_BASE_BACKOFF_MS = 250;
const DEFAULT_MAX_BACKOFF_MS = 30_000;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type RateLimitReason = 'allowed' | 'hourly_limit' | 'daily_limit' | 'backoff';

export interface RateLimitPolicy {
  readonly maxPerHour?: number;
  readonly maxPerDay?: number;
  readonly baseBackoffMs?: number;
  readonly maxBackoffMs?: number;
}

export interface RateLimitDecision {
  readonly allowed: boolean;
  readonly retryAfterMs: number;
  readonly reason: RateLimitReason;
  readonly ip: string;
  readonly timestampMs: number;
  readonly hourCount: number;
  readonly dayCount: number;
  readonly failures: number;
  readonly backoffUntil: number;
}

export interface RegistrationRateLimitEntry {
  readonly firstSeenAt: number;
  readonly lastSeenAt: number;
  readonly hourWindowStartedAt: number;
  readonly dayWindowStartedAt: number;
  readonly hourCount: number;
  readonly dayCount: number;
  readonly failures: number;
  readonly backoffUntil: number;
}

export class RegistrationRateLimitError extends Error {
  readonly name = 'RegistrationRateLimitError';
  readonly httpStatus = 429;
  readonly decision: RateLimitDecision;

  constructor(decision: RateLimitDecision) {
    super('registration rate limited');
    this.decision = decision;
  }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

interface MutableRegistrationRateLimitEntry {
  firstSeenAt: number;
  lastSeenAt: number;
  hourWindowStartedAt: number;
  dayWindowStartedAt: number;
  hourCount: number;
  dayCount: number;
  failures: number;
  backoffUntil: number;
}

interface NormalizedRateLimitPolicy {
  maxPerHour: number;
  maxPerDay: number;
  baseBackoffMs: number;
  maxBackoffMs: number;
}

export class InMemoryRateLimiter {
  private readonly policy: NormalizedRateLimitPolicy;
  private readonly entries = new Map<string, MutableRegistrationRateLimitEntry>();

  constructor(policy: RateLimitPolicy = {}) {
    this.policy = normalizePolicy(policy);
  }

  check(ip: string, now = Date.now()): RateLimitDecision {
    const normalizedIp = normalizeIp(ip);
    const entry = this.getOrCreate(normalizedIp, now);
    this.rollWindows(entry, now);
    entry.lastSeenAt = now;

    if (now < entry.backoffUntil) {
      return this.reject(entry, normalizedIp, now, 'backoff', 0);
    }

    if (entry.dayCount >= this.policy.maxPerDay) {
      const retryAfterMs = Math.max(0, entry.dayWindowStartedAt + DAY_MS - now);
      return this.reject(entry, normalizedIp, now, 'daily_limit', retryAfterMs);
    }

    if (entry.hourCount >= this.policy.maxPerHour) {
      const retryAfterMs = Math.max(0, entry.hourWindowStartedAt + HOUR_MS - now);
      return this.reject(entry, normalizedIp, now, 'hourly_limit', retryAfterMs);
    }

    entry.hourCount += 1;
    entry.dayCount += 1;
    return this.buildDecision(entry, normalizedIp, now, true, 'allowed', 0);
  }

  snapshot(ip: string): RegistrationRateLimitEntry | null {
    const entry = this.entries.get(normalizeIp(ip));
    if (entry === undefined) {
      return null;
    }
    return { ...entry };
  }

  clear(): void {
    this.entries.clear();
  }

  private getOrCreate(ip: string, now: number): MutableRegistrationRateLimitEntry {
    const existing = this.entries.get(ip);
    if (existing !== undefined) {
      return existing;
    }

    const created: MutableRegistrationRateLimitEntry = {
      firstSeenAt: now,
      lastSeenAt: now,
      hourWindowStartedAt: now,
      dayWindowStartedAt: now,
      hourCount: 0,
      dayCount: 0,
      failures: 0,
      backoffUntil: 0,
    };
    this.entries.set(ip, created);
    return created;
  }

  private rollWindows(entry: MutableRegistrationRateLimitEntry, now: number): void {
    if (now - entry.hourWindowStartedAt >= HOUR_MS) {
      entry.hourWindowStartedAt = now;
      entry.hourCount = 0;
    }
    if (now - entry.dayWindowStartedAt >= DAY_MS) {
      entry.dayWindowStartedAt = now;
      entry.dayCount = 0;
      entry.failures = 0;
      entry.backoffUntil = 0;
    }
  }

  private reject(
    entry: MutableRegistrationRateLimitEntry,
    ip: string,
    now: number,
    reason: Exclude<RateLimitReason, 'allowed'>,
    windowRetryAfterMs: number,
  ): RateLimitDecision {
    const backoffUntil = this.applyBackoff(entry, now);
    const retryAfterMs = Math.max(windowRetryAfterMs, Math.max(0, backoffUntil - now));
    return this.buildDecision(entry, ip, now, false, reason, retryAfterMs);
  }

  private applyBackoff(entry: MutableRegistrationRateLimitEntry, now: number): number {
    entry.failures += 1;
    const backoffStart = Math.max(now, entry.backoffUntil);
    entry.backoffUntil = backoffStart + calculateBackoffMs(entry.failures, this.policy);
    return entry.backoffUntil;
  }

  private buildDecision(
    entry: MutableRegistrationRateLimitEntry,
    ip: string,
    now: number,
    allowed: boolean,
    reason: RateLimitReason,
    retryAfterMs: number,
  ): RateLimitDecision {
    return {
      allowed,
      retryAfterMs,
      reason,
      ip,
      timestampMs: now,
      hourCount: entry.hourCount,
      dayCount: entry.dayCount,
      failures: entry.failures,
      backoffUntil: entry.backoffUntil,
    };
  }
}

export class InMemoryRegistrationRateLimiter extends InMemoryRateLimiter {
  constructor(policy: RateLimitPolicy = {}) {
    super({
      maxPerHour: policy.maxPerHour ?? DEFAULT_REGISTER_MAX_PER_HOUR,
      maxPerDay: policy.maxPerDay ?? DEFAULT_REGISTER_MAX_PER_DAY,
      baseBackoffMs: policy.baseBackoffMs ?? DEFAULT_BASE_BACKOFF_MS,
      maxBackoffMs: policy.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS,
    });
  }
}

// ---------------------------------------------------------------------------
// Shared default limiter / Express helper
// ---------------------------------------------------------------------------

export function createRateLimiter(policy: RateLimitPolicy = {}): InMemoryRateLimiter {
  return new InMemoryRateLimiter(policy);
}

export function createRegistrationRateLimiter(
  policy: RateLimitPolicy = {},
): InMemoryRegistrationRateLimiter {
  return new InMemoryRegistrationRateLimiter(policy);
}

export const defaultRegistrationRateLimiter = createRegistrationRateLimiter();
export const defaultAuthRateLimiter = createRateLimiter({
  maxPerHour: DEFAULT_AUTH_MAX_PER_HOUR,
  maxPerDay: DEFAULT_AUTH_MAX_PER_DAY,
  baseBackoffMs: DEFAULT_BASE_BACKOFF_MS,
  maxBackoffMs: DEFAULT_MAX_BACKOFF_MS,
});

export function checkAuthRateLimit(
  reqOrIp: Request | string,
  limiter: InMemoryRateLimiter = defaultAuthRateLimiter,
  now = Date.now(),
): RateLimitDecision {
  const ip = typeof reqOrIp === 'string' ? normalizeIp(reqOrIp) : getRequestIp(reqOrIp);
  return limiter.check(ip, now);
}

export function checkRegistrationRateLimit(
  reqOrIp: Request | string,
  limiter: InMemoryRegistrationRateLimiter = defaultRegistrationRateLimiter,
  now = Date.now(),
): RateLimitDecision {
  const ip = typeof reqOrIp === 'string' ? normalizeIp(reqOrIp) : getRequestIp(reqOrIp);
  return limiter.check(ip, now);
}

export async function enforceRegistrationRateLimit(
  req: Request,
  limiter: InMemoryRegistrationRateLimiter = defaultRegistrationRateLimiter,
): Promise<void> {
  const decision = checkRegistrationRateLimit(req, limiter);
  if (!decision.allowed) {
    throw new RegistrationRateLimitError(decision);
  }
}

export async function enforceAuthRateLimit(
  req: Request,
  limiter: InMemoryRateLimiter = defaultAuthRateLimiter,
): Promise<void> {
  const decision = checkAuthRateLimit(req, limiter);
  if (!decision.allowed) {
    throw new RegistrationRateLimitError(decision);
  }
}

export function getRequestIp(req: Request): string {
  const directIp = normalizeIp(req.ip ?? '');
  if (directIp !== 'unknown') {
    return directIp;
  }

  const forwardedFor = req.headers['x-forwarded-for'];
  if (typeof forwardedFor === 'string' && forwardedFor.length > 0) {
    return normalizeIp(forwardedFor.split(',')[0] ?? '');
  }
  if (Array.isArray(forwardedFor) && forwardedFor.length > 0) {
    return normalizeIp(forwardedFor[0] ?? '');
  }
  return 'unknown';
}

function normalizePolicy(policy: RateLimitPolicy): NormalizedRateLimitPolicy {
  const maxPerHour = sanitizePositiveInteger(policy.maxPerHour, DEFAULT_REGISTER_MAX_PER_HOUR);
  const maxPerDay = sanitizePositiveInteger(policy.maxPerDay, DEFAULT_REGISTER_MAX_PER_DAY);
  const baseBackoffMs = sanitizePositiveInteger(policy.baseBackoffMs, DEFAULT_BASE_BACKOFF_MS);
  const maxBackoffMs = Math.max(
    baseBackoffMs,
    sanitizePositiveInteger(policy.maxBackoffMs, DEFAULT_MAX_BACKOFF_MS),
  );

  return {
    maxPerHour,
    maxPerDay,
    baseBackoffMs,
    maxBackoffMs,
  };
}

function sanitizePositiveInteger(value: number | undefined, fallback: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    return fallback;
  }
  return Math.floor(value);
}

function normalizeIp(ip: string): string {
  const trimmed = ip.trim();
  return trimmed.length > 0 ? trimmed : 'unknown';
}

function calculateBackoffMs(failures: number, policy: NormalizedRateLimitPolicy): number {
  const exponent = Math.min(Math.max(failures - 1, 0), 16);
  return Math.min(policy.baseBackoffMs * 2 ** exponent, policy.maxBackoffMs);
}
