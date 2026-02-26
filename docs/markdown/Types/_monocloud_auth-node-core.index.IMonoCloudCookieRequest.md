---
rootSdk: Node.js Core
title: "IMonoCloudCookieRequest"
category: Types
---

# Type: IMonoCloudCookieRequest

Interface for reading cookies from an incoming request.

## Extended by

- [`MonoCloudRequest`](/sdks/nodejs-core/api-reference/types/monocloudrequest)
- [`MonoCloudRequest`](/sdks/nextjs/api-reference/types/monocloudrequest)

## Methods

### getAllCookies()

> **getAllCookies**(): `Promise`\<`Map`\<`string`, `string`\>\>

Retrieves all cookies from the request.

#### Returns

`Promise`\<`Map`\<`string`, `string`\>\>

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
