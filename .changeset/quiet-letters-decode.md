---
'@monocloud/auth-core': patch
---

JWT headers and claims are now decoded as UTF-8, so non-ASCII characters such as `José` or `जोस` are no longer garbled. A token whose header or payload is not valid UTF-8 is rejected with a `MonoCloudTokenError`.
