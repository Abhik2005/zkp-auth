/**
 * Compile-time constant injected by `vitest.config.ts` → `define`.
 *
 * Set to `1_000` in test builds to keep PBKDF2 fast in jsdom.
 * Not present in production builds — `typeof` guard in crypto.ts handles this.
 */
declare const __TEST_PBKDF2_ITERATIONS__: number | undefined;
