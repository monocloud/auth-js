---
'@monocloud/auth-core': patch
'@monocloud/auth-web-js': patch
'@monocloud/auth-react': patch
'@monocloud/auth-node-core': patch
'@monocloud/backend-node': patch
'@monocloud/auth-nextjs': patch
---

Correct stale README content: supported Node.js/Next.js/React version floors now match the enforced `engines`/`peerDependencies` ranges, the core feature list includes the Device Authorization Grant, the backend caching bullet is scoped to introspection results, `getSession()` is documented as returning `undefined` when signed out, and the web-js README gains Quickstart/SDK Reference links.
