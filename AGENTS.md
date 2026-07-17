# AGENTS.md

Guidance for AI agents working **on** the `@monocloud/auth-js` source. This is the monorepo for MonoCloud's JavaScript/TypeScript authentication SDKs (OAuth 2.0 / OpenID Connect) across browser, React, Node.js, and Next.js.

> **Building an app that _consumes_ these SDKs?** This file is for contributors to the SDK itself. For integration guidance, use the MonoCloud agent skills at <https://github.com/monocloud/agent-skills> (installable Claude/Cursor plugin). Each end-user package below links to its skill.

## Repository layout

pnpm workspaces (`packages/*`, depth‑1 only) + [Turborepo](turbo.json). Package manager is **pnpm** (enforced by `only-allow`; `npm`/`yarn` are blocked). Do not add nested workspaces — an `example/` dir inside a package is **not** a workspace member.

```
@monocloud/auth-core         packages/core         — framework-agnostic OIDC/OAuth primitives (zero runtime deps)
├── @monocloud/auth-web-js    packages/web-js       — browser SPA base
│   └── @monocloud/auth-react  packages/react        — React provider/hooks/components   → skill: monocloud-auth-react
├── @monocloud/auth-node-core packages/node-core    — Node session/cookie + env-backed options
│   └── @monocloud/auth-nextjs packages/nextjs       — Next.js App+Pages Router SDK       → skill: monocloud-auth-nextjs
└── @monocloud/backend-node   packages/node-backend — API access-token validation        → skills: monocloud-auth-express, monocloud-auth-fastify
@monocloud/auth-test-utils    packages/test-utils   — internal vitest setup + check-coverage CLI (not published for consumers)
```

`@monocloud/auth-web-js` also maps to the **monocloud-web-js** skill. `core` and `node-core` are internal base packages with no direct consumer skill — they are consumed by the end SDKs above.

Each package has its own `AGENTS.md` with package-specific detail. Read this root file first, then the package one.

## Architecture rules (the most important conventions)

- **End SDKs are thin wrappers, not full SDKs.** Framework packages wrap the runtime base — browser SPAs wrap `@monocloud/auth-web-js`; Node/Next wrap `@monocloud/auth-node-core`. Delegate to the base; do **not** reimplement OIDC/session logic. Keep the public surface minimal.
- **Errors:** throw the base SDK's error class (e.g. `MonoCloudJsError` from web‑js). Do **not** create per-package error classes.
- **Subpath exports:** only base packages (`core`, `web-js`, `node-core`, `node-backend`) expose `./utils` and `./internal`. End SDKs (`react`) keep a single `.` entry and import utils internally without re-exporting. `nextjs` is the exception — it splits server/client via `./client`, `./components`, `./components/client`.
- **Env-backed config (`MONOCLOUD_AUTH_*`) lives in `node-core`**, not the framework SDKs. `nextjs` consumes the resolved option and mirrors `NEXT_PUBLIC_MONOCLOUD_AUTH_*` → private for the server side. See [packages/node-core/AGENTS.md](packages/node-core/AGENTS.md).
- **The dependency arrows above are one-directional.** Never import "downward" (a base package must not depend on a framework package) and never create a cycle.

## Common commands

Run from the repo root unless noted. Turbo handles build ordering and caching.

| Task | Command | Notes |
| --- | --- | --- |
| Build all | `pnpm build` | `turbo run build` → tsdown into each `dist/` |
| Build one package | `pnpm --filter @monocloud/auth-react build` | |
| Lint all | `pnpm lint` | `lint:ts` (`tsc`, typecheck) + `lint:es` (`eslint --fix`) |
| Test all | `pnpm test` | `turbo run test` (uncached) |
| Test one package | `pnpm --filter @monocloud/auth-nextjs test` | |
| Generate docs | `pnpm gen:docs` | HTML + Markdown from JSDoc via TypeDoc |
| Docs (markdown only) | `pnpm gen:docs:markdown` | avoids the HTML `data-refl` id churn |

Per-package `test` = `eslint tests && rimraf coverage && vitest && pnpm report`, where `report` runs `nyc` and then `@monocloud/auth-test-utils check-coverage`.

## Testing & coverage

- **Vitest** with `happy-dom` (browser packages) or `node` (server packages); each config sets a junit reporter → `coverage/junit.xml` and a v8 json report. Setup comes from `@monocloud/auth-test-utils/setup`.
- **100% coverage is enforced** on every metric (statements/branches/functions/lines) by `check-coverage`. If a line is genuinely unreachable in tests (e.g. a React StrictMode guard), wrap it with `/* v8 ignore start */` … `/* v8 ignore stop */` rather than lowering the threshold.
- CI builds on Node 24; Node packages are tested across the `[20, 22, 24]` matrix, browser packages on Node 24 only. See [.github/workflows/build.yml](.github/workflows/build.yml).

## Build tooling

Every package builds with **tsdown** emitting **dual output** — `cjs` (`dts: false`) + `es` (`dts: true`), `unbundle: true`, against `tsconfig.build.json`. Browser packages mirror web‑js's tsconfig (`moduleResolution: bundler`, `target ES2020`); React/JSX packages add `jsx`. Peer deps (`express`, `fastify`, `next`, `react`) are marked `external`.

## Dependency version ceilings

Some pins are deliberate — do **not** "fix" them to latest without re-checking the constraint:

- **`typescript` 6.0.x** (root): `typedoc` and `typescript-eslint` don't support TS 7 yet (`gen:docs` and `lint` break).
- **`typescript` `^5`** in the Next.js example apps: Next 16's build-time type check fails on TS 6.
- **`cookie` 1.x** (node-core, nextjs): v2 is ESM-only (breaks the dual CJS/ESM build) and removed the `serialize` named export / 3-arg overload the SDKs use.
- **`nock` 15.0.0** (node-core, nextjs): intentionally **ahead** of npm's lagging `latest` dist-tag (14.x) — `pnpm up nock@latest` would silently downgrade it.
- **`prettier` 3.8.x** (root): the docs config sets `formatWithPrettier: true`, so `typedoc-plugin-markdown` runs the installed prettier over every page. prettier 3.9.x mangles the escaped generic close `\>` into `>\>` (renders as a stray `>`) across the generated docs — stay on 3.8.x until that regression is fixed upstream.

After a bump pass: run `pnpm dedupe`, and regenerate each Next example's `package-lock.json` from scratch (`rm -rf node_modules package-lock.json && npm install`) so the `file:`-linked metadata stays accurate.

## Docs & JSDoc

The website API reference is generated from JSDoc — **every export needs house-style docs**: summary → `@remarks` → `@example` (fenced, client examples start with `"use client"`, full public import paths) → `@param`/`@returns` → `@category` last. Valid `@category` values map to `CATEGORY_MAP` in [docs-gen/post-generate.mjs](docs-gen/post-generate.mjs). `docs/markdown` is tracked but regenerated at release — **don't commit generated docs in feature PRs**.

## Releasing

Versioning is via **Changesets** (`baseBranch: main`, `access: public`, `commit: false`). Add a changeset for any user-facing change (`pnpm changeset`). Adding a whole new package has an extended checklist (typedoc entry points, `post-generate.mjs` SDK_SLUGS, the release/build CI jobs, branch-protection checks, docs copy, and a new agent skill) — coordinate before doing it.

## Conventions

- ESLint enforces `explicit-function-return-type`; Prettier prefers `arrowParens: avoid`. Add `/* eslint-disable import/no-extraneous-dependencies */` atop test files (vitest is a root devDep).
- Match the surrounding code's style, naming, and JSDoc density. Prefer editing existing files over adding new ones.
- Commit/push only when asked; create a changeset for user-facing changes.
