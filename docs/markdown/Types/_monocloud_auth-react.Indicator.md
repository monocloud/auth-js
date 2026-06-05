---
rootSdk: @monocloud/auth-react
title: "Indicator"
category: Types
description: "Represents an additional resource indicator that can be requested when acquiring tokens."
---

# Type: Indicator

Represents an additional resource indicator that can be requested when acquiring tokens.

Resource indicators allow access tokens to be scoped to specific APIs or audiences. Multiple indicators can be configured to request tokens for different protected resources during the same authentication flow.

## Properties

| Property                         | Type     | Description                                                                           |
| -------------------------------- | -------- | ------------------------------------------------------------------------------------- |
| `resource` | `string` | Resource (or space-separated list of resources) the access token should be scoped to. |
| `scopes?`    | `string` | Optional space-separated list of scopes to request specifically for this resource.    |
