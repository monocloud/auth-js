---
rootSdk: JavaScript
title: "RefreshOptions"
category: Types
description: "Options used to customize the session refresh flow. refreshSession() exclusively uses the Refresh Token Grant."
---

# Type: RefreshOptions

Options used to customize the session refresh flow.

`refreshSession()` exclusively uses the Refresh Token Grant. To start a fresh, non-interactive authorization (e.g. on app bootstrap) use [MonoCloudWebJSClient.signInSilent](/sdks/web-js/api-reference/classes/monocloudwebjsclient#signinsilent) instead.

## Properties

| Property                                                | Type                                                                         | Description                                                                                                     |
| ------------------------------------------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `refreshGrantOptions?` | [`RefreshGrantOptions`](/sdks/web-js/api-reference/types/refreshgrantoptions) | Configuration applied to the Refresh Token Grant request, such as overriding the requested scopes or resources. |
