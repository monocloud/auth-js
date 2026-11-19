---
'@monocloud/auth-react': patch
---

`<MonoCloudAuthProvider>` now follows the client's session changes instead of re-reading storage after every action.