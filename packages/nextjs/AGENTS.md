# AGENTS.md — `@monocloud/auth-nextjs`

Authentication SDK for **Next.js** (App Router & Pages Router; Node + Edge runtimes). Provides middleware/proxy, route-protection wrappers, session/token access, and React components/hooks.

Consumer integration skill: **monocloud-auth-nextjs** (<https://github.com/monocloud/agent-skills>) — it documents the public API surface and the legacy-package pitfalls. Read [the root AGENTS.md](../../AGENTS.md) first.

## What lives here

- [src/monocloud-next-client.ts](src/monocloud-next-client.ts) — `MonoCloudNextClient`
- [src/initialize.ts](src/initialize.ts) — `authMiddleware` / `monoCloudAuth` wiring and auth routes
- [src/requests/](src/requests/) · [src/responses/](src/responses/) — Next request/response adapters
- [src/client/](src/client/) — `"use client"` surface: `useAuth`, `protectClientPage`
- [src/components/](src/components/) — `<SignIn>`/`<SignUp>`/`<SignOut>` (+ `components/client`: `<RedirectToSignIn>`, `<Protected>`)

Depends on `@monocloud/auth-node-core` + `@monocloud/auth-core` (+ `cookie`, `swr`); `next`/`react`/`react-dom` are peers.

## Server vs client split — the export map matters

| Subpath | For | Holds |
| --- | --- | --- |
| `.` | Server (RSC, route handlers, middleware/proxy, Pages API) | `authMiddleware`, `getSession`, `getTokens`, `protect`, `protectApi`, `protectPage`, `MonoCloudNextClient`, types/errors |
| `./client` | Client Components (`"use client"`) | `useAuth`, `protectClientPage` |
| `./components` | Server or Client | `<SignIn>`, `<SignUp>`, `<SignOut>` |
| `./components/client` | Client only | `<RedirectToSignIn>`, `<Protected>` |

Keep server-only code out of the `./client` and `./components/client` entry points.

## Rules specific to this package — thin wrapper over node-core

- **Delegate session/token/OIDC logic to `@monocloud/auth-node-core`.** This layer adds Next.js adapters (middleware, request/response, RSC/Edge ergonomics) and React components only.
- **Env-backed options are owned by `node-core`** — don't re-resolve `MONOCLOUD_AUTH_*` here. `registerPublicEnvVariables()` (in the constructor, before core-client init) copies `NEXT_PUBLIC_MONOCLOUD_AUTH_*` → the private equivalents so the server side picks up the public mirror. Client components (`<Protected>`, client page protection) must read `NEXT_PUBLIC_*` **directly** (browser build-time inlining) — that stays here and is documented on the `MonoCloudNextClient` JSDoc.
- Keep parity with both routers (App + Pages) and both runtimes (Node + Edge) when changing public behavior.

## Build / test

`pnpm --filter @monocloud/auth-nextjs build` · `... test` (vitest). Tested on Node `[20, 22, 24]`. 100% coverage enforced. `next`/`react` are `external` in the tsdown build.
