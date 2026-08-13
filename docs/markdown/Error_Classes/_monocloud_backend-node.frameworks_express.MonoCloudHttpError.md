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

> **new MonoCloudHttpError**(`message?`: `string`, `status?`: `number`, `statusText?`: `string`): [`MonoCloudHttpError`](/sdks/express-backend/api-reference/error-classes/monocloudhttperror)

### Parameters

| Parameter     | Type     |
| ------------- | -------- |
| `message?`    | `string` |
| `status?`     | `number` |
| `statusText?` | `string` |

### Returns

[`MonoCloudHttpError`](/sdks/express-backend/api-reference/error-classes/monocloudhttperror)

### Overrides

[`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror#constructor)

---

## status
> `readonly` `optional` **status**: `number`

HTTP status code of the response that caused the error.

Undefined when no response was received, such as a network failure.

---

## statusText
> `readonly` `optional` **statusText**: `string`

HTTP status text of the response that caused the error.
