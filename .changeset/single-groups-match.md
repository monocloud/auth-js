---
'@monocloud/auth-core': patch
---

`isUserInGroup()` now treats a string `groups` value as a single group. Previously, a string passed by an untyped caller skipped the check and returned `true` for every user.
