---
'@monocloud/auth-nextjs': patch
---

Fix `` `cookies`/`headers` was called outside a request scope `` thrown by `getSession()`/`getTokens()` in App Router Server Components and Route Handlers on Next.js 16. The build was rewriting `next/headers` to `next/headers.js`, and Next.js 16 / Turbopack only bind `cookies()`/`headers()` to the request scope for the exact `next/headers` specifier. `next/*` subpaths are now emitted as bare external specifiers.
