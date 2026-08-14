---
rootSdk: Node.js Core
title: "MonoCloudOPError"
category: Error Classes
description: "OAuth error returned by the authorization server."
---

# Error Class: MonoCloudOPError

OAuth error returned by the authorization server.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/nodejs-core/api-reference/error-classes/monocloudauthbaseerror)

## Constructors

### Constructor

> **new MonoCloudOPError**(`error`: `string`, `errorDescription?`: `string`, `raw?`: [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse)): `MonoCloudOPError`

#### Parameters

| Parameter           | Type                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------- |
| `error`             | `string`                                                                              |
| `errorDescription?` | `string`                                                                              |
| `raw?`              | [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse) |

#### Returns

`MonoCloudOPError`

#### Overrides

[`MonoCloudAuthBaseError`](/sdks/nodejs-core/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/nodejs-core/api-reference/error-classes/monocloudauthbaseerror#constructor)

## Properties

| Property                                          | Type                                                                                  | Description                                                                                                                                                          |
| ------------------------------------------------- | ------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `error`                        | `string`                                                                              | OAuth error code returned by the authorization server. When the response carries no readable error body, this is inferred from the endpoint and status code instead. |
| `errorDescription?` | `string`                                                                              | Human-readable description of the error.                                                                                                                             |
| `raw?`                           | [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse) | The raw HTTP response this error was derived from.                                                                                                                   |
