import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'auth-web-js',
    reporters: ['default', ['junit', { outputFile: 'coverage/junit.xml' }]],
    include: ['tests/**.test.ts'],
    coverage: {
      reportsDirectory: 'coverage',
      provider: 'v8',
      reporter: 'json',
      include: ['src'],
      exclude: [
        'src/types.ts',
        'src/storage.ts',
        'src/index.ts',
        'src/monocloud-js-error.ts',
        'src/utils',
      ],
      enabled: true,
      reportOnFailure: true,
    },
    environment: 'happy-dom',
    setupFiles: ['@monocloud/auth-test-utils/setup'],
    watch: false,
  },
});
