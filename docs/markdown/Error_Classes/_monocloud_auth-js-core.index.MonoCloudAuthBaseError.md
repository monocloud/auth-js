---
rootSdk: js-core
title: "MonoCloudAuthBaseError"
category: Error Classes
---

# Error Class: MonoCloudAuthBaseError

Base class for all MonoCloud authentication errors.

All errors thrown by the MonoCloud SDK extend this class, allowing applications to safely detect and handle MonoCloud-specific failures using `instanceof`.

## Extends

- `Error`

## Extended by

- [`MonoCloudTokenError`](/sdks/js-core/api-reference/error-classes/monocloudtokenerror)
- [`MonoCloudHttpError`](/sdks/js-core/api-reference/error-classes/monocloudhttperror)
- [`MonoCloudOPError`](/sdks/js-core/api-reference/error-classes/monocloudoperror)
- [`MonoCloudValidationError`](/sdks/js-core/api-reference/error-classes/monocloudvalidationerror)
- [`MonoCloudJsError`](/sdks/js-core/api-reference/error-classes/monocloudjserror)

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
