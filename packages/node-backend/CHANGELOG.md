# @monocloud/backend-node

## 0.1.9

### Patch Changes

- Updated dependencies [69ff518]
  - @monocloud/auth-core@0.1.15

## 0.1.8

### Patch Changes

- Updated dependencies [766e7f3]
  - @monocloud/auth-core@0.1.14

## 0.1.7

### Patch Changes

- e69c256: - Validate at_hash and s_hash id token claims in the implicit flow
  - Make clockTolerance configurable in node-cre and default clockSkew to 0, clockTolerance to 60
- Updated dependencies [e69c256]
  - @monocloud/auth-core@0.1.13

## 0.1.6

### Patch Changes

- 6d595b2: Parse scope from callback params and assorted test/docs fixes
- Updated dependencies [6d595b2]
  - @monocloud/auth-core@0.1.12

## 0.1.5

### Patch Changes

- d4a07a0: Update dependency package versions
- Updated dependencies [d4a07a0]
  - @monocloud/auth-core@0.1.11

## 0.1.4

### Patch Changes

- a0e6b6d: - Add comprehensive test suite for fastify framework and related utilities
- Updated dependencies [0bfdf86]
  - @monocloud/auth-core@0.1.10

## 0.1.3

### Patch Changes

- 36e1345: Removed node backend client options from Express and Fastify middlewares.

## 0.1.2

### Patch Changes

- fdf0a05: - Rename 'user' to 'claims' in authenticated request types
  - Removed `jti` claim from IdTokenClaims
- Updated dependencies [fdf0a05]
  - @monocloud/auth-core@0.1.9

## 0.1.1

### Patch Changes

- f3f475a: Added Node.js backend SDK with Express and Fastify support
- Updated dependencies [f3f475a]
  - @monocloud/auth-core@0.1.8
