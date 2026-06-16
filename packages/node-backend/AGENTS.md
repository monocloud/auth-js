# AGENTS.md — `@monocloud/backend-node`

**Access-token validation for Node.js API servers.** Validates incoming MonoCloud access tokens via JWT signature/claims verification or opaque-token introspection, with automatic format detection, scope/group authorization, optional claim caching, and mTLS certificate-bound validation. Ships first-class **Express** and **Fastify** integrations.

Consumer integration skills: **monocloud-auth-express** and **monocloud-auth-fastify** (<https://github.com/monocloud/agent-skills>). Read [the root AGENTS.md](../../AGENTS.md) first.

## What lives here

- [src/monocloud-backend-node-client.ts](src/monocloud-backend-node-client.ts) — the core validation client
- [src/get-bearer-token.ts](src/get-bearer-token.ts) — bearer extraction
- [src/options/](src/options/) — `defaults.ts`, `get-options.ts`, `validation.ts` (Joi); reads `MONOCLOUD_BACKEND_*` env vars
- [src/frameworks/express/](src/frameworks/express/) — `protectApi()` middleware factory → `./express`
- [src/frameworks/fastify/](src/frameworks/fastify/) — `protectApi()` `onRequest` hook factory → `./fastify`

Depends on `@monocloud/auth-core` (+ `joi`); `express`/`fastify` are **optional peers** (a consumer installs only the one they use). Exports: `.`, `./express`, `./fastify`, `./utils`, `./internal`.

## Rules specific to this package

- **This validates tokens; it does not run login flows** — it's distinct from the auth SDKs (`web-js`/`react`/`nextjs`/`node-core`), which obtain sessions. Keep that boundary clear.
- **Express and Fastify are parallel, isolated integrations.** Each lives under its own `frameworks/<fw>/` dir with its own entry point and is `external` in the build so the unused framework is never pulled in. Add behavior to both when it's framework-agnostic, and keep framework-specific glue in its own folder.
- Env vars here are the `MONOCLOUD_BACKEND_*` family (audience/JWKS/introspection/mTLS), resolved in [src/options/](src/options/) — separate from the `MONOCLOUD_AUTH_*` family owned by `node-core`.
- Delegate JWKS/introspection/crypto to `@monocloud/auth-core` where possible rather than reimplementing it.

## Build / test

`pnpm --filter @monocloud/backend-node build` · `... test` (vitest + `node`). Tested on Node `[20, 22, 24]`. 100% coverage enforced (framework `index.ts`/`types.ts` glue files are excluded in the vitest config).
