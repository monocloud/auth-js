---
rootSdk: Node.js Backend
title: "MonoCloudTokenError"
category: Error Classes
framework: Fastify
description: "Error thrown when a token operation fails."
---

# Error Class: MonoCloudTokenError

Error thrown when a token operation fails.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/fastify-backend/api-reference/error-classes/monocloudauthbaseerror)

## code

> `readonly` **code**: [`MonoCloudTokenErrorCode`](/sdks/fastify-backend/api-reference/enums/monocloudtokenerrorcode)

Code identifying why the token operation failed.

---

## Constructor

> **new MonoCloudTokenError**(`message?`: `string`, `code?`: [`MonoCloudTokenErrorCode`](/sdks/fastify-backend/api-reference/enums/monocloudtokenerrorcode)): [`MonoCloudTokenError`](/sdks/fastify-backend/api-reference/error-classes/monocloudtokenerror)

### Parameters

| Parameter  | Type                                                                                                     |
| ---------- | -------------------------------------------------------------------------------------------------------- |
| `message?` | `string`                                                                                                 |
| `code?`    | [`MonoCloudTokenErrorCode`](/sdks/fastify-backend/api-reference/enums/monocloudtokenerrorcode) |

### Returns

[`MonoCloudTokenError`](/sdks/fastify-backend/api-reference/error-classes/monocloudtokenerror)

### Overrides

[`MonoCloudAuthBaseError`](/sdks/fastify-backend/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/fastify-backend/api-reference/error-classes/monocloudauthbaseerror#constructor)
