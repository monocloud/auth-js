---
rootSdk: Node.js Backend
title: "MonoCloudHttpError"
category: Error Classes
framework: Express
description: "Error thrown when a request to the MonoCloud authorization server fails."
---

# Error Class: MonoCloudHttpError

Error thrown when a request to the MonoCloud authorization server fails.

This error typically indicates a network failure, an unexpected HTTP response, or an unsuccessful response returned by the authorization server.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror)

## Constructor

> **new MonoCloudHttpError**(`message?`: `string`, `raw?`: [`MonoCloudRawResponse`](/sdks/express-backend/api-reference/types/monocloudrawresponse)): [`MonoCloudHttpError`](/sdks/express-backend/api-reference/error-classes/monocloudhttperror)

### Parameters

| Parameter  | Type                                                                                     |
| ---------- | ---------------------------------------------------------------------------------------- |
| `message?` | `string`                                                                                 |
| `raw?`     | [`MonoCloudRawResponse`](/sdks/express-backend/api-reference/types/monocloudrawresponse) |

### Returns

[`MonoCloudHttpError`](/sdks/express-backend/api-reference/error-classes/monocloudhttperror)

### Inherited from

[`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror#constructor)

---

## raw
> `readonly` `optional` **raw**: [`MonoCloudRawResponse`](/sdks/express-backend/api-reference/types/monocloudrawresponse)

The raw HTTP response this error was derived from.

### Inherited from

[`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror).[`raw`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror#raw)

---

## status

### Get Signature

> **get** **status**(): `number` \| `undefined`

HTTP status code of the response that caused the error.

Undefined when no response was received, such as a network failure.

#### Returns

`number` \| `undefined`

---

## statusText

### Get Signature

> **get** **statusText**(): `string` \| `undefined`

HTTP status text of the response that caused the error.

#### Returns

`string` \| `undefined`
