---
rootSdk: Node.js Backend
title: "MonoCloudValidationError"
category: Error Classes
description: "Error thrown when validation fails."
---

# Error Class: MonoCloudValidationError

Error thrown when validation fails.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/nodejs-backend/api-reference/error-classes/monocloudauthbaseerror)

## Constructors

### Constructor

> **new MonoCloudValidationError**(`message?`: `string`, `raw?`: [`MonoCloudRawResponse`](/sdks/nodejs-backend/api-reference/types/monocloudrawresponse)): `MonoCloudValidationError`

#### Parameters

| Parameter  | Type                                                                                     |
| ---------- | ---------------------------------------------------------------------------------------- |
| `message?` | `string`                                                                                 |
| `raw?`     | [`MonoCloudRawResponse`](/sdks/nodejs-backend/api-reference/types/monocloudrawresponse) |

#### Returns

`MonoCloudValidationError`

#### Inherited from

[`MonoCloudAuthBaseError`](/sdks/nodejs-backend/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/nodejs-backend/api-reference/error-classes/monocloudauthbaseerror#constructor)

## Properties

| Property                | Type                                                                                     | Description                                        |
| ----------------------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `raw?` | [`MonoCloudRawResponse`](/sdks/nodejs-backend/api-reference/types/monocloudrawresponse) | The raw HTTP response this error was derived from. |
