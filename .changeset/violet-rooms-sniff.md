---
'@monocloud/auth-nextjs': patch
---

- **Fix:** Resolved Edge Runtime compatibility issues by removing `node:http` imports and implementing safe duck-typing for Node.js request/response checks.