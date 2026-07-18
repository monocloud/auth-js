---
'@monocloud/auth-core': patch
---

Include the `audience` and `id_token_hint` parameters in Pushed Authorization Requests (PAR). Previously they were only sent on the authorization URL, so both were silently dropped when `usePar` was enabled.
