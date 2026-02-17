---
rootSdk: Next.js
title: "ProtectedRoutes"
category: Types
---

# Type: ProtectedRoutes

> **ProtectedRoutes** = [`ProtectedRouteMatcher`](/sdks/nextjs/api-reference/types/protectedroutematcher)[] \| [`CustomProtectedRouteMatcher`](/sdks/nextjs/api-reference/handler-types/customprotectedroutematcher)

Configuration used to determine which routes require authentication.

You can provide:

- An array of [ProtectedRouteMatcher](/sdks/nextjs/api-reference/types/protectedroutematcher) values to declaratively define protected routes.
- A [CustomProtectedRouteMatcher](/sdks/nextjs/api-reference/handler-types/customprotectedroutematcher) function for fully dynamic protection logic.
