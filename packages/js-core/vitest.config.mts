import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'auth-js-core',
    include: ['tests/**.test.ts'],
    reporters: [
      'default',
      ['junit', { outputFile: 'coverage/junit.xml' }],
    ],
    coverage: {
      provider: 'v8',
      include: ['src'],
      exclude: [
        'src/types.ts',
        'src/storage.ts',
        'src/index.ts',
        'src/monocloud-js-error.ts',
        'src/utils'
      ],
      enabled: true,
      reportOnFailure: true,
      thresholds: {
        branches: 100,
        functions: 100,
        lines: 100,
        statements: 100,
      },
    },
    environment: 'happy-dom',
    setupFiles: ['@monocloud/auth-test-utils/setup'],
    watch: false,
  },
});
