---
'@monocloud/auth-web-js': patch
---

While the page is a redirect callback that `processCallback()` has not processed yet, `onSessionChange()` now holds back a listener's first value until it has.
