---
'@monocloud/auth-node-core': patch
'@monocloud/auth-nextjs': patch
'@monocloud/auth-core': patch
---

# Add initialize wrappers, rename protect client API, and overhaul docs/build pipeline

- Added initialize.ts as the top-level function API layer with lazy singleton delegation to MonoCloudNextClient, and re-exported it from index.ts.
- Renamed client page guard API from protectPage to protectClientPage (protect-client-page.tsx), updated client exports, related components, tests, and examples.
- Renamed type usage from JWSAlgorithm to SecurityAlgorithms and propagated it through core/node-core APIs.
- Added/expanded TypeDoc-friendly JSDoc categories and API comments in core/node-core/nextjs files (errors, classes, hooks, components, handler types).
- Updated OIDC client defaults in monocloud-oidc-client.ts (JWKS/metadata cache durations from 60s to 300s).
- Changed node-core default behavior in defaults.ts: allowQueryParamOverrides now defaults to true.
- Fixed text typos.
- Added split (html + markdown) docs generation:
- Added docs generation hooks/configs in docs-gen/ (including hook-html.mjs, hook.mjs, post-generate.mjs, typedoc.html.mjs, typedoc.markdown.mjs; removed typedoc.json).
- Added package-specific TypeDoc entry configs: typedoc.json, typedoc.json, typedoc.json.
- Adjusted package publishing/build setup for core/node-core: Source-based local main/types/exports with dist mapping moved under publishConfig.
- Split tsdown output configs for CJS and ESM+DTS.
- Updated Next.js examples to use package-level helper exports directly (removed example-local monocloud.ts files) and refreshed route matcher examples.
