import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'nextjs-auth-node',
    include: [
      'tests/config.test.ts',
      'tests/middleware.test.ts',
      'tests/server-functions/**/**.test.ts',
      'tests/monocloud-auth/**/**.test.ts',
      'tests/utils.test.ts',
      'tests/public-env.test.ts',
    ],
    coverage: {
      reportsDirectory: 'coverage/node',
      reporter: 'json',
      provider: 'v8',
      include: ['src'],
      exclude: [
        'node_modules',
        'src/global.d.ts',
        'src/index.ts',
        'src/types',
        'src/client/index.tsx',
        'src/components/index.tsx',
        'src/components/client/index.tsx',
      ],
      enabled: true,
      reportOnFailure: true,
    },
    environment: 'node',
    setupFiles: ['./tests/setup.ts'],
    watch: false,
  },
});
