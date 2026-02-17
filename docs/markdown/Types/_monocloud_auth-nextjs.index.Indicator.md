---
rootSdk: Next.js
title: "Indicator"
category: Types
---

# Type: Indicator

Represents an additional resource indicator that can be requested during token acquisition.

Resource indicators allow an access token to be scoped to a specific API or service (audience). Multiple indicators may be provided when requesting tokens for different protected resources.

## Properties

| Property                         | Type     | Description                                                                                                                                                             |
| -------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `resource` | `string` | Space-separated list of resource identifiers (audiences) that the access token should be issued for. Each value typically represents an API identifier or resource URI. |
| `scopes?`    | `string` | Optional. Space-separated list of scopes to request specifically for this resource.                                                                                     |
