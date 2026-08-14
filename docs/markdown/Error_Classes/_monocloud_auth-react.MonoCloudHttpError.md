---
rootSdk: React
title: "MonoCloudHttpError"
category: Error Classes
description: "Error thrown when a request to the MonoCloud authorization server fails."
---

# Error Class: MonoCloudHttpError

Error thrown when a request to the MonoCloud authorization server fails.

This error typically indicates a network failure, an unexpected HTTP response, or an unsuccessful response returned by the authorization server.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/react/api-reference/error-classes/monocloudauthbaseerror)

## Constructors

### Constructor

> **new MonoCloudHttpError**(`message?`: `string`, `raw?`: [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse)): `MonoCloudHttpError`

#### Parameters

| Parameter  | Type                                                                                  |
| ---------- | ------------------------------------------------------------------------------------- |
| `message?` | `string`                                                                              |
| `raw?`     | [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse) |

#### Returns

`MonoCloudHttpError`

#### Inherited from

[`MonoCloudAuthBaseError`](/sdks/react/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/react/api-reference/error-classes/monocloudauthbaseerror#constructor)

## Properties

| Property                | Type                                                                                  | Description                                        |
| ----------------------- | ------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `raw?` | [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse) | The raw HTTP response this error was derived from. |

## Accessors

### status

#### Get Signature

> **get** **status**(): `number` \| `undefined`

HTTP status code of the response that caused the error.

Undefined when no response was received, such as a network failure.

##### Returns

`number` \| `undefined`

---

### statusText

#### Get Signature

> **get** **statusText**(): `string` \| `undefined`

HTTP status text of the response that caused the error.

##### Returns

`string` \| `undefined`
