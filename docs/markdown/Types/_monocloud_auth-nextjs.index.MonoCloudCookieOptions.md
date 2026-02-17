---
rootSdk: Next.js
title: "MonoCloudCookieOptions"
category: Types
---

# Type: MonoCloudCookieOptions

Configuration options for authentication cookies.

These settings control how MonoCloud session and state cookies are created, scoped, and transmitted by the browser.

## Properties

| Property                             | Type                                                                                  | Description                                                                                                                                                                               |
| ------------------------------------ | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `domain?`        | `string`                                                                              | Optional domain scope for the cookie.                                                                                                                                                     |
| `httpOnly`     | `boolean`                                                                             | Indicates whether the cookie is accessible only via HTTP requests. Helps mitigate XSS attacks by preventing client-side JavaScript access. > Always enforced as `true` for state cookies. |
| `name`             | `string`                                                                              | The cookie name. - Session cookie default: `"session"` - State cookie default: `"state"`                                                                                                  |
| `path`             | `string`                                                                              | The URL path for which the cookie is valid.                                                                                                                                               |
| `persistent` | `boolean`                                                                             | Determines whether the cookie persists across browser restarts. - Session cookies default to `true` - State cookies default to `false`                                                    |
| `sameSite`     | [`SameSiteValues`](/sdks/nextjs/api-reference/enums/samesitevalues) | The SameSite policy applied to the cookie. Controls cross-site request behavior and CSRF protection.                                                                                      |
| `secure`         | `boolean`                                                                             | Indicates whether the cookie should only be transmitted over HTTPS. If not explicitly provided, this value is automatically inferred from the application URL scheme.                     |
