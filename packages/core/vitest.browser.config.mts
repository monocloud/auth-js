import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'core-js-auth-browser',
    include: ['tests/**.test.ts'],
    coverage: {
      reportsDirectory: 'coverage/browser',
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
    environment: 'happy-dom',
    setupFiles: ['@monocloud/auth-test-utils/setup'],
    watch: false,
  },
});
