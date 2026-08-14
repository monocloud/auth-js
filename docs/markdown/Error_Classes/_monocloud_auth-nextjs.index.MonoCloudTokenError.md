---
rootSdk: Next.js
title: "MonoCloudTokenError"
category: Error Classes
description: "Error thrown when a token operation fails."
---

# Error Class: MonoCloudTokenError

Error thrown when a token operation fails.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/nextjs/api-reference/error-classes/monocloudauthbaseerror)

## Constructors

### Constructor

> **new MonoCloudTokenError**(`message?`: `string`, `code?`: [`MonoCloudTokenErrorCode`](/sdks/nodejs/api-reference/enums/monocloudtokenerrorcode), `raw?`: [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse)): `MonoCloudTokenError`

#### Parameters

| Parameter  | Type                                                                                                  |
| ---------- | ----------------------------------------------------------------------------------------------------- |
| `message?` | `string`                                                                                              |
| `code?`    | [`MonoCloudTokenErrorCode`](/sdks/nodejs/api-reference/enums/monocloudtokenerrorcode) |
| `raw?`     | [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse)                 |

#### Returns

`MonoCloudTokenError`

#### Overrides

[`MonoCloudAuthBaseError`](/sdks/nextjs/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/nextjs/api-reference/error-classes/monocloudauthbaseerror#constructor)

## Properties

| Property                 | Type                                                                                                  | Description                                        |
| ------------------------ | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `code` | [`MonoCloudTokenErrorCode`](/sdks/nodejs/api-reference/enums/monocloudtokenerrorcode) | Code identifying why the token operation failed.   |
| `raw?`  | [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse)                 | The raw HTTP response this error was derived from. |
