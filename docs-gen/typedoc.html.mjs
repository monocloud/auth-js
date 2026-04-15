/** @type {import("typedoc").TypeDocOptions} */
const config = {
  packageOptions: {
    gitRevision: 'main',
    includeVersion: false,
    excludeExternals: true,
    excludeInternal: true,
    excludePrivate: true,
    excludeNotDocumented: false,
    sortEntryPoints: true,
    disableGit: false,
    disableSources: false,
    sort: 'alphabetical',
  },
  entryPoints: [
    '../packages/core',
    '../packages/node-core',
    '../packages/nextjs',
    '../packages/node-backend',
  ],
  exclude: [
    '**/dist/**',
    '**/node_modules/**',
    '**/tests/**',
    '**/examples/**',
    '**/packages/test-utils',
  ],
  visibilityFilters: [],
  includeHierarchySummary: false,
  sortEntryPoints: false,
  entryPointStrategy: 'packages',
  out: '../docs/html',
  name: 'MonoCloud Authentication SDK',
  readme: '../README.md',
  hideGenerator: true,
  disableSources: false,
  categorizeByGroup: false,
  theme: 'default',
  validation: {
    notExported: true,
    invalidLink: true,
    notDocumented: false,
  },
  plugin: ['./hook-html.mjs'],
};

export default config;
