---
rootSdk: Node.js
title: "MonoCloudTokenError"
category: Error Classes
description: "Error thrown when a token operation fails."
---

# Error Class: MonoCloudTokenError

Error thrown when a token operation fails.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/nodejs/api-reference/error-classes/monocloudauthbaseerror)

## Constructors

### Constructor

> **new MonoCloudTokenError**(`message?`: `string`, `code?`: [`MonoCloudTokenErrorCode`](/sdks/nodejs/api-reference/enums/monocloudtokenerrorcode)): `MonoCloudTokenError`

#### Parameters

| Parameter  | Type                                                                                                  |
| ---------- | ----------------------------------------------------------------------------------------------------- |
| `message?` | `string`                                                                                              |
| `code?`    | [`MonoCloudTokenErrorCode`](/sdks/nodejs/api-reference/enums/monocloudtokenerrorcode) |

#### Returns

`MonoCloudTokenError`

#### Overrides

[`MonoCloudAuthBaseError`](/sdks/nodejs/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/nodejs/api-reference/error-classes/monocloudauthbaseerror#constructor)

## Properties

| Property                 | Type                                                                                                  | Description                                      |
| ------------------------ | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| `code` | [`MonoCloudTokenErrorCode`](/sdks/nodejs/api-reference/enums/monocloudtokenerrorcode) | Code identifying why the token operation failed. |
