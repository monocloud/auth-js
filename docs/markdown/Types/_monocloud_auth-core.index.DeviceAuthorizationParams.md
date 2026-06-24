---
rootSdk: Node.js
title: "DeviceAuthorizationParams"
category: Types
description: "Parameters used to construct an OAuth 2.0 / OpenID Connect device authorization request."
---

# Type: DeviceAuthorizationParams

Parameters used to construct an OAuth 2.0 / OpenID Connect device authorization request.

## Properties

| Property                          | Type     | Description                                                                     |
| --------------------------------- | -------- | ------------------------------------------------------------------------------- |
| `resource?` | `string` | Space-separated list of resource indicators that scope the issued access token. |
| `scopes?`     | `string` | Space-separated list of scopes requested during authentication.                 |
