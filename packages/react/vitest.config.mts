import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'auth-react',
    reporters: ['default', ['junit', { outputFile: 'coverage/junit.xml' }]],
    include: ['tests/**.test.{ts,tsx}'],
    coverage: {
      reportsDirectory: 'coverage',
      provider: 'v8',
      reporter: 'json',
      include: ['src'],
      exclude: ['src/types.ts', 'src/index.ts', 'src/components/index.tsx'],
      enabled: true,
      reportOnFailure: true,
    },
    environment: 'happy-dom',
    setupFiles: ['./tests/setup.ts'],
    watch: false,
  },
});
