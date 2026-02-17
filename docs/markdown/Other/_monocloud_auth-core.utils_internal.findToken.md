---
rootSdk: Node.js
title: "findToken"
category: Other
---

# findToken

> **findToken**(`tokens?`: [`AccessToken`](/sdks/nodejs/api-reference/types/accesstoken)[], `resource?`: `string`, `scopes?`: `string`): [`AccessToken`](/sdks/nodejs/api-reference/types/accesstoken) \| `undefined`

Finds a specific access token in an array based on resource and scopes.

## Parameters

| Parameter   | Type                                                                  | Description                          |
| ----------- | --------------------------------------------------------------------- | ------------------------------------ |
| `tokens?`   | [`AccessToken`](/sdks/nodejs/api-reference/types/accesstoken)[] | The array of access tokens.          |
| `resource?` | `string`                                                              | Space-separated resource indicators. |
| `scopes?`   | `string`                                                              | Space-separated scopes.              |

## Returns

[`AccessToken`](/sdks/nodejs/api-reference/types/accesstoken) \| `undefined`

The matching AccessToken, or `undefined` if not found.
