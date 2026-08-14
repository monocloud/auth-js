---
rootSdk: Node.js Backend
title: "MonoCloudOPError"
category: Error Classes
framework: Express
description: "OAuth error returned by the authorization server."
---

# Error Class: MonoCloudOPError

OAuth error returned by the authorization server.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror)

## Constructor

> **new MonoCloudOPError**(`error`: `string`, `errorDescription?`: `string`, `raw?`: [`MonoCloudRawResponse`](/sdks/express-backend/api-reference/types/monocloudrawresponse)): [`MonoCloudOPError`](/sdks/express-backend/api-reference/error-classes/monocloudoperror)

### Parameters

| Parameter           | Type                                                                                     |
| ------------------- | ---------------------------------------------------------------------------------------- |
| `error`             | `string`                                                                                 |
| `errorDescription?` | `string`                                                                                 |
| `raw?`              | [`MonoCloudRawResponse`](/sdks/express-backend/api-reference/types/monocloudrawresponse) |

### Returns

[`MonoCloudOPError`](/sdks/express-backend/api-reference/error-classes/monocloudoperror)

### Overrides

[`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror#constructor)

---

## error

> **error**: `string`

OAuth error code returned by the authorization server.

When the response carries no readable error body, this is inferred from the endpoint and status code instead.

---

## errorDescription
> `optional` **errorDescription**: `string`

Human-readable description of the error.

---

## raw
> `readonly` `optional` **raw**: [`MonoCloudRawResponse`](/sdks/express-backend/api-reference/types/monocloudrawresponse)

The raw HTTP response this error was derived from.

### Inherited from

[`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror).[`raw`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror#raw)
