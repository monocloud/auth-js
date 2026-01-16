---
'@monocloud/auth-nextjs': patch
---

- Fixed an error where Next.js Request was created incorrectly that throws an error on Node.js 24
- Added duplex property to Next.js Request creation in utils to support Node.js streaming response
- Refactored Next.js response creation from raw response
- Added tests for the utils method `getNextRequest()` and `getNextResponse()`
