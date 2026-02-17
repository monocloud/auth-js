---
rootSdk: Next.js
title: "MonoCloudAuthBaseError"
category: Error Classes
---

# Error Class: MonoCloudAuthBaseError

Base class for all MonoCloud authentication errors.

All errors thrown by the MonoCloud SDK extend this class, allowing applications to safely detect and handle MonoCloud-specific failures using `instanceof`.

## Extends

- `Error`

## Extended by

- [`MonoCloudValidationError`](/sdks/nextjs/api-reference/error-classes/monocloudvalidationerror)
- [`MonoCloudHttpError`](/sdks/nextjs/api-reference/error-classes/monocloudhttperror)
- [`MonoCloudOPError`](/sdks/nextjs/api-reference/error-classes/monocloudoperror)
- [`MonoCloudTokenError`](/sdks/nextjs/api-reference/error-classes/monocloudtokenerror)

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
