# AGENTS.md — `@monocloud/auth-test-utils`

**Internal** testing utilities shared across the workspace — not a consumer-facing SDK and not published for app developers. Provides the vitest setup, HTTP/storage/window mocks, a mock auth server, and the coverage gate.

Read [the root AGENTS.md](../../AGENTS.md) first.

## What lives here

- [src/setup.ts](src/setup.ts) — vitest setup, consumed by every package via `setupFiles: ['@monocloud/auth-test-utils/setup']`
- [src/check-coverage.js](src/check-coverage.js) — the `check-coverage` **bin**; run by each package's `report` script to enforce **100%** on all metrics
- [src/mock-http.ts](src/mock-http.ts) · [src/mock-storage.ts](src/mock-storage.ts) · [src/mock-window.ts](src/mock-window.ts) · [src/auth-server-fetch.ts](src/auth-server-fetch.ts) — shared mocks/helpers

`jose` and `vitest` are peers (provided by the root). Exports: `.`, `./setup`. Bin: `check-coverage`. **Source is consumed directly (no build step)** — there is no `build`/`test` script, only `lint`.

## Rules specific to this package

- **Changes here ripple to every package's test run.** A change to `setup.ts`, the mocks, or `check-coverage.js` affects the whole monorepo's CI — verify across packages before changing shared behavior.
- This package itself has no tests/coverage gate; keep new helpers small, generic, and reusable rather than package-specific.
- Don't add it as a runtime dependency of any shipped package — it is a dev/test dependency only.

## Commands

`pnpm --filter @monocloud/auth-test-utils lint`. No build/test step.
