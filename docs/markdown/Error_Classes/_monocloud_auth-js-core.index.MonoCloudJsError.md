---
rootSdk: js-core
title: "MonoCloudJsError"
category: Error Classes
---

# Error Class: MonoCloudJsError

Base class for all MonoCloud authentication errors.

All errors thrown by the MonoCloud SDK extend this class, allowing applications to safely detect and handle MonoCloud-specific failures using `instanceof`.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/js-core/api-reference/error-classes/monocloudauthbaseerror)

## Constructors

### Constructor

> **new MonoCloudJsError**(`message?`: `string`): `MonoCloudJsError`

#### Parameters

| Parameter  | Type     |
| ---------- | -------- |
| `message?` | `string` |

#### Returns

`MonoCloudJsError`

#### Inherited from

[`MonoCloudAuthBaseError`](/sdks/js-core/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/js-core/api-reference/error-classes/monocloudauthbaseerror#constructor)
