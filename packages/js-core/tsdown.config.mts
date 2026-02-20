import { defineConfig } from 'tsdown';

const common = {
  tsconfig: './tsconfig.build.json',
  entry: ['src/index.ts', 'src/utils/index.ts', 'src/utils/internal.ts'],
  sourcemap: true,
  minify: true,
  noExternal: ['browser-tabs-lock'],
  inlineOnly: ['browser-tabs-lock'],
};

export default defineConfig([
  { ...common, format: 'cjs', dts: false },
  { ...common, format: 'es', dts: true },
]);
