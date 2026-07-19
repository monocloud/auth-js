# AGENTS.md — `@monocloud/auth-node-core`

High-level **server-side** authentication client for Node.js: Authorization Code Flow with PKCE, encrypted-cookie session management, automatic token rotation, and state/CSRF validation. Framework-agnostic — it is the **base that `@monocloud/auth-nextjs` builds on**.

Read [the root AGENTS.md](../../AGENTS.md) first. This is an internal base package (no direct consumer skill).

## What lives here

- [src/monocloud-node-core-client.ts](src/monocloud-node-core-client.ts) — the main server client
- [src/monocloud-session-service.ts](src/monocloud-session-service.ts) / [src/monocloud-state-service.ts](src/monocloud-state-service.ts) — encrypted cookie sessions + state/CSRF
- [src/options/](src/options/) — `defaults.ts`, `get-options.ts`, `validation.ts` (Joi)
- [src/types/](src/types/) — `MonoCloudOptionsBase` / `MonoCloudOptions`

Depends on `@monocloud/auth-core` (+ `cookie`, `jose`, `joi`, `uuid`, `debug`). Exports: `.`, `./utils`, `./internal`.

## This package owns env-backed config (`MONOCLOUD_AUTH_*`)

`MONOCLOUD_AUTH_*` options are resolved **here**, not in the framework SDKs — `nextjs` consumes the resolved option. To add one, touch all of:

- [src/types/index.ts](src/types/index.ts) — add the field to `MonoCloudOptionsBase` with a JSDoc `@defaultValue`; also add a row to the "Environment Variables" table in the `MonoCloudOptions` JSDoc.
- [src/options/defaults.ts](src/options/defaults.ts) — add to `DEFAULT_OPTIONS`.
- [src/options/get-options.ts](src/options/get-options.ts) — resolve `opt.field = options?.field ?? process.env.MONOCLOUD_AUTH_X ?? DEFAULT_OPTIONS.field`.
- [src/options/validation.ts](src/options/validation.ts) — add to the Joi `optionsSchema`.

Resolved options are read **once at client construction** (`getOptions()` returns the cached `this.options`), not lazily per call — env must be set before constructing the client.

## Rules specific to this package

- **Delegate OIDC to `@monocloud/auth-core`**; this layer adds Node session/cookie/state handling only.
- Server-only (Node ≥ 20). Keep browser concerns out.

## Build / test

`pnpm --filter @monocloud/auth-node-core build` · `... test` (vitest + `node`). Tested on Node `[20, 22, 24]`. 100% coverage enforced.
