import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    globalSetup: ['test/global-setup.ts'],
    // Database tests share one database; run files sequentially for determinism.
    fileParallelism: false,
    testTimeout: 20000,
    hookTimeout: 60000,
  },
});
