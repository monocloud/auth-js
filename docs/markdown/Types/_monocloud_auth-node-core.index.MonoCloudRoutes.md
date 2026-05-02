---
rootSdk: Node.js Core
title: "MonoCloudRoutes"
category: Types
description: "Route configuration for MonoCloud authentication handlers."
---

# Type: MonoCloudRoutes

Route configuration for MonoCloud authentication handlers.

These routes define the internal application endpoints used by the SDK to process authentication flows such as sign-in, callback handling, sign-out, and user profile retrieval.

You typically do not need to change these values unless you want to customize your application's authentication URLs.

> When customizing routes, ensure the corresponding URLs are also configured in your MonoCloud Dashboard and exposed to the client using the matching environment variables.

## Properties

| Property                                           | Type     | Description                                                                                      |
| -------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------ |
| `backChannelLogout` | `string` | Route that handles OpenID Connect back-channel logout requests initiated by MonoCloud.           |
| `callback`                   | `string` | Route that receives the authorization callback from MonoCloud after a successful authentication. |
| `signIn`                       | `string` | Route used to initiate the sign-in flow.                                                         |
| `signOut`                     | `string` | Route used to initiate the sign-out flow.                                                        |
| `userInfo`                   | `string` | Route that exposes the authenticated user's profile information.                                 |
