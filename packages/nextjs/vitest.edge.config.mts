import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'nextjs-auth-edge',
    include: [
      'tests/middleware.test.ts',
      'tests/server-functions/**/*.app-router.test.ts',
      'tests/monocloud-auth/**/*.app-router.test.ts',
      'tests/config.test.ts',
      'tests/utils.test.ts',
      'tests/public-env.test.ts',
    ],
    coverage: {
      reportsDirectory: 'coverage/edge',
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
    environment: 'edge-runtime',
    setupFiles: ['./tests/setup.ts'],
    watch: false,
  },
});
