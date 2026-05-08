import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'node-auth-backend-node',
    reporters: [
      'default',
      ['junit', { outputFile: 'coverage/junit.xml' }],
    ],
    include: ['tests/**/**.test.ts'],
    coverage: {
      reportsDirectory: 'coverage',
      provider: 'v8',
      reporter: 'json',
      include: ['src'],
      exclude: [
        'src/types.ts',
        'src/utils',
        'src/index.ts',
        'src/frameworks/express/index.ts',
        'src/frameworks/express/types.ts',
        'src/frameworks/fastify/index.ts',
        'src/frameworks/fastify/types.ts',
        'tests/frameworks/helpers.ts',
      ],
      enabled: true,
      reportOnFailure: true,
    },
    environment: 'node',
    setupFiles: ['@monocloud/auth-test-utils/setup'],
    watch: false,
  },
});
