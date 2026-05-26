---
rootSdk: Node.js Backend
title: "MonoCloudOPError"
category: Error Classes
framework: Express
description: "OAuth error returned by the authorization server during an authentication or token request."
---

# Error Class: MonoCloudOPError

OAuth error returned by the authorization server during an authentication or token request.

These errors correspond to standard OAuth / OpenID Connect error responses such as `invalid_request`, `access_denied`, or `invalid_grant`.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror)

## Constructor

> **new MonoCloudOPError**(`error`: `string`, `errorDescription?`: `string`): [`MonoCloudOPError`](/sdks/express-backend/api-reference/error-classes/monocloudoperror)

### Parameters

| Parameter           | Type     |
| ------------------- | -------- |
| `error`             | `string` |
| `errorDescription?` | `string` |

### Returns

[`MonoCloudOPError`](/sdks/express-backend/api-reference/error-classes/monocloudoperror)

### Overrides

[`MonoCloudAuthBaseError`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/express-backend/api-reference/error-classes/monocloudauthbaseerror#constructor)

---

## error

> **error**: `string`

OAuth error code returned by the authorization server.

---

## errorDescription
> `optional` **errorDescription**: `string`

Human-readable description of the error.
