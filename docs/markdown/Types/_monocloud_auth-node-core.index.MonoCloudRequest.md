---
rootSdk: Node.js Core
title: "MonoCloudRequest"
category: Types
description: "Represents a request object that includes cookie handling capabilities."
---

# Type: MonoCloudRequest

Represents a request object that includes cookie handling capabilities.

## Extends

- [`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest)

## Methods

### getAllCookies()

> **getAllCookies**(): `Promise`\<`Map`\<`string`, `string`\>\>

Retrieves all cookies from the request.

#### Returns

`Promise`\<`Map`\<`string`, `string`\>\>

#### Inherited from

[`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest).[`getAllCookies`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest#getallcookies)

---

### getCookie()

> **getCookie**(`name`: `string`): `Promise`\<`string` \| `undefined`\>

Retrieves a single cookie value by name.

#### Parameters

| Parameter | Type     | Description                         |
| --------- | -------- | ----------------------------------- |
| `name`    | `string` | The name of the cookie to retrieve. |

#### Returns

`Promise`\<`string` \| `undefined`\>

#### Inherited from

[`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest).[`getCookie`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest#getcookie)

---

### getQuery()

> **getQuery**(`parameter`: `string`): `string` \| `string`[] \| `undefined`

Retrieves a query parameter value by name.

#### Parameters

| Parameter   | Type     | Description                                  |
| ----------- | -------- | -------------------------------------------- |
| `parameter` | `string` | The name of the query parameter to retrieve. |

#### Returns

`string` \| `string`[] \| `undefined`

---

### getRawRequest()

> **getRawRequest**(): `Promise`\<\{ `body`: `string` \| `Record`\<`string`, `string`\>; `method`: `string`; `url`: `string`; \}\>

Returns the raw request details including method, URL, and body.

#### Returns

`Promise`\<\{ `body`: `string` \| `Record`\<`string`, `string`\>; `method`: `string`; `url`: `string`; \}\>
