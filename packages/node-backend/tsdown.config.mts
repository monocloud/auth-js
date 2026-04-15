import { defineConfig } from 'tsdown';

const common = {
  tsconfig: './tsconfig.build.json',
  entry: {
    index: 'src/index.ts',
    'express': 'src/frameworks/express/index.ts',
    'fastify': 'src/frameworks/fastify/index.ts',
    'utils/index': 'src/utils/index.ts',
    'utils/internal': 'src/utils/internal.ts',
  },
  clean: true,
  sourcemap: true,
  external: ['express', 'fastify', '@types/express', '@types/express-serve-static-core']
};

export default defineConfig([
  { ...common, format: 'cjs', dts: false },
  { ...common, format: 'es', dts: true },
]);
