---
'@monocloud/auth-core': patch
'@monocloud/auth-web-js': patch
---

- Match the `openid` scope exactly instead of substring-testing the granted scope string.