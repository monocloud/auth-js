---
rootSdk: Node.js Backend
title: "MonoCloudValidationError"
category: Error Classes
framework: Fastify
description: "Error thrown when validation fails."
---

# Error Class: MonoCloudValidationError

Error thrown when validation fails.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/fastify-backend/api-reference/error-classes/monocloudauthbaseerror)

## Constructor

> **new MonoCloudValidationError**(`message?`: `string`, `raw?`: [`MonoCloudRawResponse`](/sdks/fastify-backend/api-reference/types/monocloudrawresponse)): [`MonoCloudValidationError`](/sdks/fastify-backend/api-reference/error-classes/monocloudvalidationerror)

### Parameters

| Parameter  | Type                                                                                     |
| ---------- | ---------------------------------------------------------------------------------------- |
| `message?` | `string`                                                                                 |
| `raw?`     | [`MonoCloudRawResponse`](/sdks/fastify-backend/api-reference/types/monocloudrawresponse) |

### Returns

[`MonoCloudValidationError`](/sdks/fastify-backend/api-reference/error-classes/monocloudvalidationerror)

### Inherited from

[`MonoCloudAuthBaseError`](/sdks/fastify-backend/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/fastify-backend/api-reference/error-classes/monocloudauthbaseerror#constructor)

---

## raw
> `readonly` `optional` **raw**: [`MonoCloudRawResponse`](/sdks/fastify-backend/api-reference/types/monocloudrawresponse)

The raw HTTP response this error was derived from.

### Inherited from

[`MonoCloudAuthBaseError`](/sdks/fastify-backend/api-reference/error-classes/monocloudauthbaseerror).[`raw`](/sdks/fastify-backend/api-reference/error-classes/monocloudauthbaseerror#raw)
