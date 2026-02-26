---
rootSdk: Next.js
title: "SameSiteValues"
category: Enums
---

# Enum: SameSiteValues

> **SameSiteValues** = `"strict"` \| `"lax"` \| `"none"`

Allowed values for the cookie `SameSite` attribute.

The `SameSite` setting controls when cookies are included in cross-site requests and helps protect against cross-site request forgery (CSRF) attacks.

## Type Declaration

- `strict` - Cookies are only sent for same-site requests. Cookies will NOT be included in cross-site navigations, redirects, or embedded requests. Provides the strongest CSRF protection but may break authentication flows that rely on cross-site redirects.
- `lax` - Cookies are sent for same-site requests and top-level cross-site navigations (for example, following a link). This is the recommended default for most authentication flows.
- `none` - Cookies are sent with all requests, including cross-site requests. Must be used together with `Secure=true` (HTTPS only). Required for some third-party or cross-origin authentication scenarios.
