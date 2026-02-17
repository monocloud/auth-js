---
rootSdk: Next.js
title: "MonoCloudOPError"
category: Error Classes
---

# Error Class: MonoCloudOPError

OAuth error returned by the authorization server during an authentication or token request.

These errors correspond to standard OAuth / OpenID Connect error responses such as `invalid_request`, `access_denied`, or `invalid_grant`.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/nextjs/api-reference/error-classes/monocloudauthbaseerror)

## Constructors

### Constructor

> **new MonoCloudOPError**(`error`: `string`, `errorDescription?`: `string`): `MonoCloudOPError`

#### Parameters

| Parameter           | Type     |
| ------------------- | -------- |
| `error`             | `string` |
| `errorDescription?` | `string` |

#### Returns

`MonoCloudOPError`

#### Overrides

[`MonoCloudAuthBaseError`](/sdks/nextjs/api-reference/error-classes/monocloudauthbaseerror).[`constructor`](/sdks/nextjs/api-reference/error-classes/monocloudauthbaseerror#constructor)

## Properties

| Property                                          | Type     | Description                                            |
| ------------------------------------------------- | -------- | ------------------------------------------------------ |
| `error`                        | `string` | OAuth error code returned by the authorization server. |
| `errorDescription?` | `string` | Human-readable description of the error.               |
