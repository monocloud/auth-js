---
rootSdk: JavaScript
title: "MonoCloudValidationError"
category: Error Classes
description: "Error thrown when validation fails."
---

# Error Class: MonoCloudValidationError

Error thrown when validation fails.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/web-js/api-reference/error-classes/monocloudauthbaseerror)

## Constructors

### Constructor

> **new MonoCloudValidationError**(`message?`: `string`, `raw?`: [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse)): `MonoCloudValidationError`

#### Parameters

| Parameter  | Type                                                                                  |
| ---------- | ------------------------------------------------------------------------------------- |
| `message?` | `string`                                                                              |
| `raw?`     | [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse) |

#### Returns

`MonoCloudValidationError`

#### Inherited from

[`MonoCloudAuthBaseError`](/sdks/web-js/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/web-js/api-reference/error-classes/monocloudauthbaseerror#constructor)

## Properties

| Property                | Type                                                                                  | Description                                        |
| ----------------------- | ------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `raw?` | [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse) | The raw HTTP response this error was derived from. |
