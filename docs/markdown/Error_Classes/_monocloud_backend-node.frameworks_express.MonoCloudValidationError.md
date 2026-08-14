---
rootSdk: Node.js Backend
title: "MonoCloudValidationError"
category: Error Classes
framework: Express
description: "Error thrown when validation fails."
---

# Error Class: MonoCloudValidationError

Error thrown when validation fails.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror)

## Constructor

> **new MonoCloudValidationError**(`message?`: `string`, `raw?`: [`MonoCloudRawResponse`](/sdks/express-backend/api-reference/types/monocloudrawresponse)): [`MonoCloudValidationError`](/sdks/express-backend/api-reference/error-classes/monocloudvalidationerror)

### Parameters

| Parameter  | Type                                                                                     |
| ---------- | ---------------------------------------------------------------------------------------- |
| `message?` | `string`                                                                                 |
| `raw?`     | [`MonoCloudRawResponse`](/sdks/express-backend/api-reference/types/monocloudrawresponse) |

### Returns

[`MonoCloudValidationError`](/sdks/express-backend/api-reference/error-classes/monocloudvalidationerror)

### Inherited from

[`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror#constructor)

---

## raw
> `readonly` `optional` **raw**: [`MonoCloudRawResponse`](/sdks/express-backend/api-reference/types/monocloudrawresponse)

The raw HTTP response this error was derived from.

### Inherited from

[`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror).[`raw`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror#raw)
