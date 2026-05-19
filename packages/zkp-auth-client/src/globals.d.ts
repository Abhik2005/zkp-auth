/**
 * Compile-time constant injected by `vitest.config.ts` → `define`.
 *
 * Set to `64` (KB) in test builds so Argon2id is fast in jsdom.
 * Not present in production builds — `typeof` guard in key-storage.ts handles this.
 */
declare const __TEST_ARGON2_MEMORY__: number | undefined;
