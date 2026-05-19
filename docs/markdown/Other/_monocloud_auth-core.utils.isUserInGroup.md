---
rootSdk: Node.js
title: "isUserInGroup"
category: Other
description: "Checks if a user is a member of a specified group or groups."
---

# isUserInGroup

> **isUserInGroup**(`user`: [`MonoCloudUser`](/sdks/nodejs/api-reference/types/monoclouduser) \| [`IdTokenClaims`](/sdks/nodejs/api-reference/types/idtokenclaims), `groups`: `string`[], `groupsClaim`: `string`, `matchAll`: `boolean`): `boolean`

Checks if a user is a member of a specified group or groups.

## Parameters

| Parameter     | Type                                                                                                                                               | Description                                                                                                                  |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `user`        | [`MonoCloudUser`](/sdks/nodejs/api-reference/types/monoclouduser) \| [`IdTokenClaims`](/sdks/nodejs/api-reference/types/idtokenclaims) | The user.                                                                                                                    |
| `groups`      | `string`[]                                                                                                                                         | An array of group names or IDs to check membership against.                                                                  |
| `groupsClaim` | `string`                                                                                                                                           | The claim in the user object that contains groups.                                                                           |
| `matchAll`    | `boolean`                                                                                                                                          | If `true`, requires the user to be in all specified groups; if `false`, checks if the user is in at least one of the groups. |

## Returns

`boolean`

`true` if the user is in the specified groups, `false` otherwise.
