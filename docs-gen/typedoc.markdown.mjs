// TypeDoc config driving the controlled markdown emitter (emitter.mjs).
//
// The markdown docs are produced entirely by our own emitter + render/* layer
// (see manifest.mjs for the knobs). typedoc-plugin-markdown is no longer used.
// Reflection options below mirror what the old pipeline used so the converted
// project is identical; only the rendering (output) layer is ours.

/** @type {import("typedoc").TypeDocOptions} */
const config = {
  plugin: ['./emitter.mjs'],
  entryPoints: [
    '../packages/core',
    '../packages/web-js',
    '../packages/react',
    '../packages/node-core',
    '../packages/nextjs',
    '../packages/node-backend',
  ],
  entryPointStrategy: 'packages',
  packageOptions: {
    gitRevision: 'main',
    includeVersion: false,
    excludeExternals: true,
    excludeInternal: true,
    excludePrivate: true,
    excludeProtected: true,
    excludeNotDocumented: false,
    sortEntryPoints: true,
    disableGit: true,
    disableSources: true,
    sort: 'alphabetical',
  },
  exclude: [
    '**/dist/**',
    '**/node_modules/**',
    '**/tests/**',
    '**/example/**',
    '**/examples/**',
    '**/packages/test-utils',
  ],
  outputs: [{ name: 'monocloud-markdown', path: '../docs/markdown' }],
  name: 'MonoCloud Authentication SDK',
  readme: '../README.md',
  hideGenerator: true,
  validation: { notExported: false, invalidLink: false, notDocumented: false },
};

export default config;
