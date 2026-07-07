const packageScopes = [
  'core',
  'nextjs',
  'node-backend',
  'node-core',
  'react',
  'test-utils',
  'web-js',
];

const metaScopes = ['repo', 'deps', 'release', 'ci', '*'];

const configuration = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'body-max-line-length': [1, 'always', 150],
    'scope-enum': [2, 'always', [...packageScopes, ...metaScopes]],
    'subject-case': [1, 'always', ['camel-case', 'lower-case', 'sentence-case']],
  },
};

export default configuration;
