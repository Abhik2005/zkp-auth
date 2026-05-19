import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'jsdom',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
    },
    testTimeout: 30_000, // Argon2id at low memory is still slower than PBKDF2
  },
  define: {
    // Override Argon2id memory cost in test builds for speed.
    // key-storage.ts reads __TEST_ARGON2_MEMORY__ at module init; production
    // builds have no define so the constant falls back to 65_536 (64 MB).
    __TEST_ARGON2_MEMORY__: 64, // 64 KB — fast but still exercises the real code path
  },
});
