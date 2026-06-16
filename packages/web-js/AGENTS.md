# AGENTS.md — `@monocloud/auth-web-js`

Browser-side authentication SDK for **single-page apps** and any in-browser JavaScript. Implements OAuth 2.0 / OIDC with PKCE, redirect/popup/silent flows, and session + token management. It is the **base for higher-level browser framework SDKs** (React lives here in the repo; Vue/Angular/Svelte/Astro are intended consumers).

Consumer integration skill: **monocloud-web-js** (<https://github.com/monocloud/agent-skills>). Read [the root AGENTS.md](../../AGENTS.md) first.

## What lives here

- [src/monocloud-web-js-client.ts](src/monocloud-web-js-client.ts) — `MonoCloudWebJSClient`, the public client (`signIn`/`signOut`/`signInSilent`/`getTokens`/`getSession`/`processCallback`, etc.)
- [src/storage.ts](src/storage.ts) — `LocalStorage` / `SessionStorage` / `MemoryStorage` strategies
- [src/monocloud-js-error.ts](src/monocloud-js-error.ts) — `MonoCloudJsError`, the error class **the React SDK re-throws** (don't add a new one downstream)
- [src/lock.ts](src/lock.ts) / [src/ref.ts](src/ref.ts) — cross-tab lock (`browser-tabs-lock`) and refs
- [src/utils/](src/utils/) — exposed via `./utils` (e.g. `isUserInGroup`, consumed internally by React)

Depends on `@monocloud/auth-core`. Exports: `.`, `./utils`, `./internal`.

## Rules specific to this package

- **This is the browser base** — React (and future browser SDKs) wrap it as thin layers. Auth/session/token logic belongs here, not in the framework wrapper.
- Browser-only: builds against the bundler tsconfig (`moduleResolution: bundler`, `target ES2020`). Keep runtime-agnostic OIDC concerns in `core`.
- Navigation/callback behavior is exposed via the `postCallback` option so framework wrappers can avoid a full-page reload — keep that seam intact rather than baking in bespoke redirect props.

## Build / test

`pnpm --filter @monocloud/auth-web-js build` · `... test` (vitest + `happy-dom`, Node 24). 100% coverage enforced.
