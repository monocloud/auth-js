import { defineConfig } from 'tsdown';

export default defineConfig({
  tsconfig: './tsconfig.build.json',
  entry: ['src/index.ts','src/utils/index.ts','src/utils/internal.ts'],
  sourcemap: true,
  dts: true,
  format: ['cjs', 'esm'],
});
