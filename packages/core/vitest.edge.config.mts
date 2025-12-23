import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'core-js-auth-edge',
    include: ['tests/**.test.ts'],
    coverage: {
      reportsDirectory: 'coverage/edge',
      reporter: 'json',
      provider: 'v8',
      include: ['src'],
      exclude: [
        'node_modules',
        'src/errors',
        'src/types',
        'tests',
        'src/index.ts',
      ],
      enabled: true,
      reportOnFailure: true,
    },
    environment: 'edge-runtime',
    setupFiles: ['@monocloud/auth-test-utils/setup'],
    watch: false,
  },
});
