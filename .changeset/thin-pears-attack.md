---
'@monocloud/auth-core': patch
---

Require the `cnf` confirmation claim to be a JSON object, per RFC 7800. A `cnf` carried as a JSON-encoded string is no longer parsed and is rejected with `The 'cnf' claim could not be parsed`.
