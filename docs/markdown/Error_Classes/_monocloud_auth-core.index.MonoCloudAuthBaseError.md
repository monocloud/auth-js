---
rootSdk: Node.js
title: "MonoCloudAuthBaseError"
category: Error Classes
---

# Error Class: MonoCloudAuthBaseError

Base class for all MonoCloud authentication errors.

All errors thrown by the MonoCloud SDK extend this class, allowing applications to safely detect and handle MonoCloud-specific failures using `instanceof`.

## Extends

- `Error`

## Extended by

- [`MonoCloudOPError`](/sdks/nodejs/api-reference/error-classes/monocloudoperror)
- [`MonoCloudHttpError`](/sdks/nodejs/api-reference/error-classes/monocloudhttperror)
- [`MonoCloudTokenError`](/sdks/nodejs/api-reference/error-classes/monocloudtokenerror)
- [`MonoCloudValidationError`](/sdks/nodejs/api-reference/error-classes/monocloudvalidationerror)

## Constructors

### Constructor

> **new MonoCloudAuthBaseError**(`message?`: `string`): `MonoCloudAuthBaseError`

#### Parameters

| Parameter  | Type     |
| ---------- | -------- |
| `message?` | `string` |

#### Returns

`MonoCloudAuthBaseError`

#### Inherited from

`Error.constructor`
