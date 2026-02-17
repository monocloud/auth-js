---
rootSdk: Node.js Core
title: "MonoCloudHttpError"
category: Error Classes
---

# Error Class: MonoCloudHttpError

Error thrown when a request to the MonoCloud authorization server fails.

This error typically indicates a network failure, an unexpected HTTP response, or an unsuccessful response returned by the authorization server.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/nodejs-core/api-reference/error-classes/monocloudauthbaseerror)

## Constructors

### Constructor

> **new MonoCloudHttpError**(`message?`: `string`): `MonoCloudHttpError`

#### Parameters

| Parameter  | Type     |
| ---------- | -------- |
| `message?` | `string` |

#### Returns

`MonoCloudHttpError`

#### Inherited from

[`MonoCloudAuthBaseError`](/sdks/nodejs-core/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/nodejs-core/api-reference/error-classes/monocloudauthbaseerror#constructor)
