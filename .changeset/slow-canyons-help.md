---
'@monocloud/auth-nextjs': patch
---

- Resolve the claim from the core option at the group-check call sites
  instead of reading `process.env` directly; the standalone `isUserInGroup`
  method defers to node-core's resolution. `NEXT_PUBLIC_MONOCLOUD_AUTH_GROUPS_CLAIM`
  is unchanged for client components.
