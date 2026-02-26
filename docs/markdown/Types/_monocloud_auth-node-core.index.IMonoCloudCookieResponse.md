---
rootSdk: Node.js Core
title: "IMonoCloudCookieResponse"
category: Types
---

# Type: IMonoCloudCookieResponse

Interface for setting cookies on an outgoing response.

## Extended by

- [`MonoCloudResponse`](/sdks/nodejs-core/api-reference/types/monocloudresponse)

## Methods

### setCookie()

> **setCookie**(`cookieName`: `string`, `value`: `string`, `options`: [`CookieOptions`](/sdks/nodejs-core/api-reference/types/cookieoptions)): `Promise`\<`void`\>

Sets a cookie on the response.

#### Parameters

| Parameter    | Type                                                                | Description                           |
| ------------ | ------------------------------------------------------------------- | ------------------------------------- |
| `cookieName` | `string`                                                            | The name of the cookie to set.        |
| `value`      | `string`                                                            | The value to assign to the cookie.    |
| `options`    | [`CookieOptions`](/sdks/nodejs-core/api-reference/types/cookieoptions) | Serialization options for the cookie. |

#### Returns

`Promise`\<`void`\>
