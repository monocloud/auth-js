import { defineConfig } from 'tsdown';

const common = {
  tsconfig: './tsconfig.build.json',
  entry: ['src/index.ts', 'src/utils/index.ts', 'src/utils/internal.ts'],
  clean: true,
  sourcemap: true,
};

export default defineConfig([
  { ...common, format: 'cjs', dts: false },
  { ...common, format: 'es', dts: true },
]);
