import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'node-auth-core-edge',
    include: ['tests/**/**.test.ts'],
    coverage: {
      reportsDirectory: 'coverage/edge',
      provider: 'v8',
      reporter: 'json',
      include: ['src'],
      exclude: ['tests/test-helpers.ts', 'src/utils', 'src/types', 'src/index.ts'],
      enabled: true,
      reportOnFailure: true,
    },
    environment: 'edge-runtime',
    setupFiles: ['./tests/setup.ts'],
    watch: false,
  },
});
