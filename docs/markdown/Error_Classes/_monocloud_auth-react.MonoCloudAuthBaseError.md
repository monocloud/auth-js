---
rootSdk: @monocloud/auth-react
title: "MonoCloudAuthBaseError"
category: Error Classes
description: "Base class for all MonoCloud authentication errors."
---

# Error Class: MonoCloudAuthBaseError

Base class for all MonoCloud authentication errors.

All errors thrown by the MonoCloud SDK extend this class, allowing applications to safely detect and handle MonoCloud-specific failures using `instanceof`.

## Extends

- `Error`

## Extended by

- [`MonoCloudJsError`](/sdks/react/api-reference/error-classes/monocloudjserror)
- [`MonoCloudOPError`](/sdks/react/api-reference/error-classes/monocloudoperror)
- [`MonoCloudValidationError`](/sdks/react/api-reference/error-classes/monocloudvalidationerror)
- [`MonoCloudTokenError`](/sdks/react/api-reference/error-classes/monocloudtokenerror)
- [`MonoCloudHttpError`](/sdks/react/api-reference/error-classes/monocloudhttperror)

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
