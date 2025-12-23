import eslint from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import tseslint from 'typescript-eslint';
import importPlugin from 'eslint-plugin-import';
import prettierPluginRecomended from 'eslint-plugin-prettier/recommended';
import globals from 'globals';
import reactPlugin from 'eslint-plugin-react';
import reacthook from 'eslint-plugin-react-hooks';

export default defineConfig([
  eslint.configs.recommended,
  reactPlugin.configs.flat.recommended,
  tseslint.configs.recommended,
  tseslint.configs.stylisticTypeChecked,
  importPlugin.flatConfigs.recommended,
  importPlugin.flatConfigs.typescript,
  prettierPluginRecomended,
  reacthook.configs.flat.recommended,
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      globals: globals.node,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    settings: {
      'import/resolver': {
        typescript: {
          alwaysTryTypes: true,
          project: '.',
        },
      },
    },
    rules: {
      'no-console': 'warn',
      'consistent-return': 'error',
      'no-unreachable': 'error',
      'no-unreachable-loop': 'error',
      'require-await': 'warn',
      'no-unused-vars': 'off',
      'no-restricted-syntax': 'error',
      'no-nested-ternary': 'warn',
      '@typescript-eslint/no-use-before-define': 'warn',
      '@typescript-eslint/class-methods-use-this': 'off',
      '@typescript-eslint/no-empty-function': 'off',
      '@typescript-eslint/no-confusing-void-expression': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-non-null-assertion': 'warn',
      '@typescript-eslint/explicit-function-return-type': 'error',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/prefer-for-of': 'off',
      '@typescript-eslint/no-redeclare': 'error',
      '@typescript-eslint/no-dynamic-delete': 'error',
      '@typescript-eslint/only-throw-error': 'error',
      'func-names': ['warn', 'as-needed'],
      'object-curly-newline': ['warn', { consistent: true }],
      'spaced-comment': ['warn', 'always', { markers: ['/'] }],
      'import/no-extraneous-dependencies': [
        'error',
        {
          devDependencies: [
            '**/*.test.*',
            '**/*.spec.*',
            '**/tests/**',
            '**/*.config.*',
            '**/scripts/**',
            '**/tooling/**',
          ],
          optionalDependencies: false,
          peerDependencies: true,
        },
      ],
      'no-use-before-define': 'off',
      '@typescript-eslint/no-use-before-define': [
        'error',
        {
          functions: false,
          classes: true,
          variables: true,
          enums: true,
          typedefs: true,
        },
      ],
      'no-shadow': 'off',
      '@typescript-eslint/no-shadow': ['error'],
      'import/prefer-default-export': 'off',
      'import/extensions': [
        'error',
        'ignorePackages',
        {
          js: 'never',
          mjs: 'never',
          jsx: 'never',
          ts: 'never',
          tsx: 'never',
          dts: 'never',
        },
      ],
      'no-underscore-dangle': [
        'warn',
        { allowAfterThis: true, allowAfterSuper: true },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: 'LabeledStatement',
          message: 'Labels are confusing and prone to errors.',
        },
        {
          selector: 'WithStatement',
          message: '`with` is disallowed in strict mode.',
        },
        {
          selector: 'ForInStatement',
          message: 'Use Object.keys/entries with hasOwn checks instead.',
        },
      ],
      'prefer-arrow-callback': [
        'error',
        { allowNamedFunctions: false, allowUnboundThis: true },
      ],
      'prefer-destructuring': [
        'warn',
        {
          VariableDeclarator: { array: false, object: true },
          AssignmentExpression: { array: false, object: false },
        },
        { enforceForRenamedProperties: false },
      ],
      'no-plusplus': ['error', { allowForLoopAfterthoughts: true }],
      'no-param-reassign': ['error', { props: true }],
      'lines-between-class-members': ['error', 'always'],
    },
  },
  globalIgnores([
    'node_modules',
    'dist',
    '.turbo',
    "packages/test-utils/src/check-coverage.js",
  ]),
]);
