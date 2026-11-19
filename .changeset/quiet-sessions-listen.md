---
'@monocloud/auth-web-js': patch
---

- Added `onSessionChange(listener)` to `MonoCloudWebJSClient`, with the exported `SessionChangeListener` type. The listener receives the stored session once, then every session the client writes (or `undefined` when it is removed), in write order and before `postCallback` runs. It returns a function that removes the listener.
