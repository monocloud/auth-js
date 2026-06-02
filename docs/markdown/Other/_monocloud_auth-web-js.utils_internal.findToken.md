---
rootSdk: JavaScript
title: "findToken"
category: Other
description: "Finds a specific access token in an array based on resource and scopes."
---

# findToken

> **findToken**(`tokens?`: [`AccessToken`](/sdks/web-js/api-reference/types/accesstoken)[], `resource?`: `string`, `scopes?`: `string`): [`AccessToken`](/sdks/web-js/api-reference/types/accesstoken) \| `undefined`

Finds a specific access token in an array based on resource and scopes.

## Parameters

| Parameter   | Type                                                                    | Description                          |
| ----------- | ----------------------------------------------------------------------- | ------------------------------------ |
| `tokens?`   | [`AccessToken`](/sdks/web-js/api-reference/types/accesstoken)[] | The array of access tokens.          |
| `resource?` | `string`                                                                | Space-separated resource indicators. |
| `scopes?`   | `string`                                                                | Space-separated scopes.              |

## Returns

[`AccessToken`](/sdks/web-js/api-reference/types/accesstoken) \| `undefined`

The matching AccessToken, or `undefined` if not found.
