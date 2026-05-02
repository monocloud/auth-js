---
rootSdk: Node.js Core
title: "MonoCloudResponse"
category: Types
description: "Represents an outgoing HTTP response with common helper methods."
---

# Type: MonoCloudResponse

Represents an outgoing HTTP response with common helper methods.

## Extends

- [`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse)

## Methods

### done()

> **done**(): `any`

Finalizes and returns the response.

#### Returns

`any`

---

### internalServerError()

> **internalServerError**(): `void`

Sends a 500 Internal Server Error response.

#### Returns

`void`

---

### methodNotAllowed()

> **methodNotAllowed**(): `void`

Sends a 405 Method Not Allowed response.

#### Returns

`void`

---

### noContent()

> **noContent**(): `void`

Sends a 204 No Content response.

#### Returns

`void`

---

### notFound()

> **notFound**(): `void`

Sends a 404 Not Found response.

#### Returns

`void`

---

### redirect()

> **redirect**(`url`: `string`, `statusCode?`: `number`): `void`

Redirects the client to the specified URL.

#### Parameters

| Parameter     | Type     | Description                                   |
| ------------- | -------- | --------------------------------------------- |
| `url`         | `string` | The URL to redirect to.                       |
| `statusCode?` | `number` | The HTTP status code to use for the redirect. |

#### Returns

`void`

---

### sendJson()

> **sendJson**(`data`: `any`, `statusCode?`: `number`): `void`

Sends a JSON response with an optional status code.

#### Parameters

| Parameter     | Type     | Description                             |
| ------------- | -------- | --------------------------------------- |
| `data`        | `any`    | The data to serialize and send as JSON. |
| `statusCode?` | `number` | The HTTP status code for the response.  |

#### Returns

`void`

---

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

#### Inherited from

[`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse).[`setCookie`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse#setcookie)

---

### setNoCache()

> **setNoCache**(): `void`

Sets cache-control headers to prevent caching.

#### Returns

`void`
