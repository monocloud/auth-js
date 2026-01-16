---
'@monocloud/auth-core': patch
---

- fix JSON error assertion for Node > 20. Node.js updated JSON.parse error messages to include line/column numbers in newer versions. Updated the message to assert according to the running Node version.
