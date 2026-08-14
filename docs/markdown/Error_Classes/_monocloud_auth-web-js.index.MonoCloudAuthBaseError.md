---
rootSdk: JavaScript
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

- [`MonoCloudTokenError`](/sdks/web-js/api-reference/error-classes/monocloudtokenerror)
- [`MonoCloudHttpError`](/sdks/web-js/api-reference/error-classes/monocloudhttperror)
- [`MonoCloudOPError`](/sdks/web-js/api-reference/error-classes/monocloudoperror)
- [`MonoCloudValidationError`](/sdks/web-js/api-reference/error-classes/monocloudvalidationerror)
- [`MonoCloudJsError`](/sdks/web-js/api-reference/error-classes/monocloudjserror)

## Constructors

### Constructor

> **new MonoCloudAuthBaseError**(`message?`: `string`, `raw?`: [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse)): `MonoCloudAuthBaseError`

#### Parameters

| Parameter  | Type                                                                                  |
| ---------- | ------------------------------------------------------------------------------------- |
| `message?` | `string`                                                                              |
| `raw?`     | [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse) |

#### Returns

`MonoCloudAuthBaseError`

#### Overrides

`Error.constructor`

## Properties

| Property                | Type                                                                                  | Description                                        |
| ----------------------- | ------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `raw?` | [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse) | The raw HTTP response this error was derived from. |
