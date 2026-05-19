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

> **new MonoCloudHttpError**(`message?`: `string`): [`MonoCloudHttpError`](/sdks/express-backend/api-reference/error-classes/monocloudhttperror)

### Parameters

| Parameter  | Type     |
| ---------- | -------- |
| `message?` | `string` |

### Returns

[`MonoCloudHttpError`](/sdks/express-backend/api-reference/error-classes/monocloudhttperror)

### Inherited from

[`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror#constructor)
