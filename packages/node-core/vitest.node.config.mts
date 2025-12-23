import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'node-auth-core-node',
    include: ['tests/**/**.test.ts'],
    coverage: {
      reportsDirectory: 'coverage/node',
      provider: 'v8',
      reporter: 'json',
      include: ['src'],
      exclude: [
        'tests/test-helpers.ts',
        'src/types',
        'src/utils',
        'src/index.ts',
      ],
      enabled: true,
      reportOnFailure: true,
    },
    environment: 'node',
    setupFiles: ['./tests/setup.ts'],
    watch: false,
  },
});
