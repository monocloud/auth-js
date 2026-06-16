# AGENTS.md — `@monocloud/auth-react`

React authentication SDK for **single-page applications** (React 18+). Surfaces auth state, sign-in/out flows, and route protection through a provider, hooks, and components.

Consumer integration skill: **monocloud-auth-react** (<https://github.com/monocloud/agent-skills>). Read [the root AGENTS.md](../../AGENTS.md) first.

## What lives here

- [src/monocloud-auth-provider.tsx](src/monocloud-auth-provider.tsx) — `<MonoCloudAuthProvider>`, constructs the underlying web‑js client once
- [src/use-auth.tsx](src/use-auth.tsx) — `useAuth` hook (auth state + actions)
- [src/use-client.tsx](src/use-client.tsx) / [src/use-process-callback.tsx](src/use-process-callback.tsx) — client access + callback handling
- [src/components/](src/components/) — sign-in/out and protection components
- [src/context.ts](src/context.ts) — React context

Depends on `@monocloud/auth-web-js`; `react`/`react-dom` are peers. **Single `.` export.**

## Rules specific to this package — it is a thin wrapper

- **Delegate everything to `@monocloud/auth-web-js`.** This package adds React ergonomics (provider/hooks/components) only — no reimplemented auth logic.
- **Throw `MonoCloudJsError`** from web‑js; do not add a React-specific error class.
- **Import web‑js utils internally** (e.g. `isUserInGroup` from `@monocloud/auth-web-js/utils`) but **do not re-export** them — keep the single `.` entry.
- Forward web‑js's `postCallback` straight to the client at construction (set once, never reassigned); a thin default avoids a full-page reload. No bespoke `onRedirect`-style props.
- Build tsconfig adds `jsx: "react"` on top of the browser tsconfig. Example apps use the Vite + React-TS template (not CRA) and depend on the SDK via `file:../`; `example/` is not a workspace member.

## Build / test

`pnpm --filter @monocloud/auth-react build` · `... test` (vitest + `happy-dom`, Node 24). 100% coverage enforced — wrap StrictMode-only guards in `/* v8 ignore start|stop */`.
