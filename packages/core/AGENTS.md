# AGENTS.md — `@monocloud/auth-core`

Framework-agnostic **OpenID Connect / OAuth 2.0** client and primitives. This is the foundation of the monorepo — `web-js`, `node-core`, and `node-backend` all build on it. Runtime-agnostic (Node ≥ 16 with `fetch` + Web Crypto, and modern browsers) with **zero runtime dependencies**.

Read [the root AGENTS.md](../../AGENTS.md) first for monorepo-wide commands, tooling, and conventions.

## What lives here

Authorization Code Flow, PKCE, Pushed Authorization Requests (PAR), token lifecycle, and the shared error types. Key source:

- [src/monocloud-oidc-client-base.ts](src/monocloud-oidc-client-base.ts) — shared OIDC client logic
- [src/monocloud-oidc-client.ts](src/monocloud-oidc-client.ts) / [src/monocloud-oidc-backend-client.ts](src/monocloud-oidc-backend-client.ts) — public/backend clients
- [src/client-auth.ts](src/client-auth.ts) — client authentication methods
- [src/errors/](src/errors/) — the canonical error classes (re-thrown by downstream packages — see root rule "do not create per-package error classes")
- [src/utils/](src/utils/) — exposed via the `./utils` subpath

Exports: `.`, `./utils`, `./internal`.

## Rules specific to this package

- **This package owns the OIDC primitives.** Logic that belongs to "how OAuth/OIDC works" goes here, not in a framework SDK. Downstream packages should delegate to these clients.
- **Keep it dependency-free and runtime-agnostic** — no Node-only or browser-only APIs in the public path; rely on standard `fetch` and Web Crypto. Node/browser-specific behavior belongs in `node-core` / `web-js`.
- Errors thrown here are the ones every other package surfaces — change them with care and a changeset.

## Build / test

`pnpm --filter @monocloud/auth-core build` · `... test`. Tested on Node `[20, 22, 24]`. 100% coverage enforced.
