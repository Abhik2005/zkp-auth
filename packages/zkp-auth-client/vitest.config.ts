import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'jsdom',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
    },
    testTimeout: 15_000,  // generous headroom for any slow async crypto in CI
  },
  define: {
    // Override PBKDF2 iterations in test builds for speed.
    // crypto.ts reads __TEST_PBKDF2_ITERATIONS__ at module init; production
    // builds have no define so the constant falls back to 600_000.
    __TEST_PBKDF2_ITERATIONS__: 1_000,
  },
});
