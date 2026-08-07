---
rootSdk: Next.js
title: "MonoCloudStateCookieOptions"
category: Types
description: "Configuration options for the authentication state cookie."
---

# Type: MonoCloudStateCookieOptions

Configuration options for the authentication state cookie.

## Extends

- `Omit`\<[`MonoCloudCookieOptions`](/sdks/nextjs/api-reference/types/monocloudcookieoptions), `"persistent"`\>

## Properties

| Property                         | Type                                                                                  | Description                                                                                                                                                                             |
| -------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `domain?`    | `string`                                                                              | Optional domain scope for the cookie.                                                                                                                                                   |
| `httpOnly` | `boolean`                                                                             | Indicates whether the cookie is accessible only via HTTP requests. Helps mitigate XSS attacks by preventing client-side JavaScript access. Always enforced as `true` for state cookies. |
| `name`         | `string`                                                                              | The cookie name. Defaults to `"session"` for session cookies and `"state"` for state cookies.                                                                                           |
| `path`         | `string`                                                                              | The URL path for which the cookie is valid.                                                                                                                                             |
| `sameSite` | [`SameSiteValues`](/sdks/nextjs/api-reference/enums/samesitevalues) | The SameSite policy applied to the cookie. Controls cross-site request behavior and CSRF protection.                                                                                    |
| `secure`     | `boolean`                                                                             | Indicates whether the cookie should only be transmitted over HTTPS. If not explicitly provided, this value is automatically inferred from the application URL scheme.                   |
