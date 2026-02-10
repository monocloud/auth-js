---
'@monocloud/auth-nextjs': patch
---

- Split the single onAccessDenied callback into distinct handlers for unauthenticated vs unauthorized (group) scenarios across server-side APIs, SSR pages, and middleware
- Add onGroupAccessDenied for server-side (App Router, Page Router, middleware) — receives the authenticated user object, only fires on group check failures
- Rename client-side onAccessDenied to fallback / groupFallback for the protectPage HOC and <Protected> component
- Added tests: group fallback behavior, priority of onGroupAccessDenied over onAccessDenied, no fallback leakage between auth and group denial paths
- Update getSession Page Router doc example with improved typing (satisfies GetServerSideProps)
