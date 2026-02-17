---
rootSdk: Node.js Core
title: "ParResponse"
category: Types
---

# Type: ParResponse

Response returned from the Pushed Authorization Request (PAR) endpoint.

## Properties

| Property                               | Type     | Description                                                                                                                                                                         |
| -------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `expires_in`   | `number` | Lifetime of the `request_uri`, in seconds. After this duration expires, the authorization request becomes invalid.                                                                  |
| `request_uri` | `string` | The URI reference identifying the pushed authorization request. This value must be supplied as the `request_uri` parameter when redirecting the user to the authorization endpoint. |
