import { defineConfig } from 'tsdown';

export default defineConfig({
  tsconfig: './tsconfig.build.json',
  entry: ['src/index.ts', 'src/utils/index.ts', 'src/utils/internal.ts'],
  dts: {
    resolve: true,
  },
  clean: true,
  sourcemap: true,
  outDir: 'dist',
  format: ['esm', 'cjs']
});
