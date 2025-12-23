import { defineConfig } from 'tsdown';
import pkg from './package.json' with { type: 'json' };

const common = {
  tsconfig: './tsconfig.build.json',
  entry: [
    'src/index.ts',
    'src/client/index.tsx',
    'src/components/index.tsx',
    'src/components/client/index.tsx',
  ],
  clean: true,
  sourcemap: true,
  define: {
    SDK_NAME: `"${pkg.name}"`,
    SDK_VERSION: `"${pkg.version}"`,
    SDK_DEBUGGER_NAME: `"${pkg.name.replace('/', ':')}"`,
  },
};

export default defineConfig([
  { ...common, format: 'cjs', dts: false },
  { ...common, format: 'es', dts: true },
]);
