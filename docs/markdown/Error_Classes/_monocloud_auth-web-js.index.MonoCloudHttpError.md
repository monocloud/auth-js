---
rootSdk: JavaScript
title: "MonoCloudHttpError"
category: Error Classes
description: "Error thrown when a request to the MonoCloud authorization server fails."
---

# Error Class: MonoCloudHttpError

Error thrown when a request to the MonoCloud authorization server fails.

This error typically indicates a network failure, an unexpected HTTP response, or an unsuccessful response returned by the authorization server.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/web-js/api-reference/error-classes/monocloudauthbaseerror)

## Constructors

### Constructor

> **new MonoCloudHttpError**(`message?`: `string`, `status?`: `number`, `statusText?`: `string`): `MonoCloudHttpError`

#### Parameters

| Parameter     | Type     |
| ------------- | -------- |
| `message?`    | `string` |
| `status?`     | `number` |
| `statusText?` | `string` |

#### Returns

`MonoCloudHttpError`

#### Overrides

[`MonoCloudAuthBaseError`](/sdks/web-js/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/web-js/api-reference/error-classes/monocloudauthbaseerror#constructor)

## Properties

| Property                              | Type     | Description                                                                                                                 |
| ------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------- |
| `status?`         | `number` | HTTP status code of the response that caused the error. Undefined when no response was received, such as a network failure. |
| `statusText?` | `string` | HTTP status text of the response that caused the error.                                                                     |
