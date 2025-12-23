import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'nextjs-auth-browser',
    include: ['tests/client/**.test.{ts,tsx}'],
    coverage: {
      reportsDirectory: 'coverage/browser',
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
    environment: 'happy-dom',
    setupFiles: ['./tests/setup.ts'],
    watch: false,
  },
});
