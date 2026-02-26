---
rootSdk: js-core
title: "Indicator"
category: Types
---

# Type: Indicator

Represents an additional resource indicator that can be requested when acquiring tokens.

## Properties

| Property                         | Type     | Description                                                     |
| -------------------------------- | -------- | --------------------------------------------------------------- |
| `resource` | `string` | Space-separated list of resources to scope the access token to. |
| `scopes?`    | `string` | Optional space-separated list of scopes to request.             |
