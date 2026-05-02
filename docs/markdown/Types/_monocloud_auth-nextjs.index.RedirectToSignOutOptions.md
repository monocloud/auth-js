---
rootSdk: Next.js
title: "RedirectToSignOutOptions"
category: Types
description: "Options for redirectToSignOut()."
---

# Type: RedirectToSignOutOptions

Options for [redirectToSignOut()](/sdks/nextjs/api-reference/functions/redirecttosignout).

## Properties

| Property                                                    | Type      | Description                                                                                                                                                                                 |
| ----------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `federated?`                         | `boolean` | When enabled, the user is also signed out from MonoCloud (Single Sign-Out).                                                                                                                 |
| `postLogoutRedirectUri?` | `string`  | URL where the authorization server should redirect the user after a successful sign-out. This value must match one of the registered Sign-out Redirect URLs configured for the application. |
