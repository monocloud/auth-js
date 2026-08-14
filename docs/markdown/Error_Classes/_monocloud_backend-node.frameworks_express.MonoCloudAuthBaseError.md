---
rootSdk: Node.js Backend
title: "MonoCloudAuthBaseError"
category: Error Classes
framework: Express
description: "Base class for all MonoCloud authentication errors."
---

# Error Class: MonoCloudAuthBaseError

Base class for all MonoCloud authentication errors.

All errors thrown by the MonoCloud SDK extend this class, allowing applications to safely detect and handle MonoCloud-specific failures using `instanceof`.

## Extends

- `Error`

## Constructor

> **new MonoCloudAuthBaseError**(`message?`: `string`, `raw?`: [`MonoCloudRawResponse`](/sdks/express-backend/api-reference/types/monocloudrawresponse)): [`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror)

### Parameters

| Parameter  | Type                                                                                     |
| ---------- | ---------------------------------------------------------------------------------------- |
| `message?` | `string`                                                                                 |
| `raw?`     | [`MonoCloudRawResponse`](/sdks/express-backend/api-reference/types/monocloudrawresponse) |

### Returns

[`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror)

### Overrides

`Error.constructor`

---

## raw
> `readonly` `optional` **raw**: [`MonoCloudRawResponse`](/sdks/express-backend/api-reference/types/monocloudrawresponse)

The raw HTTP response this error was derived from.
