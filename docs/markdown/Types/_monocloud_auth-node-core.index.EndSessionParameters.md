---
rootSdk: Node.js Core
title: "EndSessionParameters"
category: Types
description: "Parameters used to construct an OpenID Connect end-session (sign-out) request."
---

# Type: EndSessionParameters

Parameters used to construct an OpenID Connect end-session (sign-out) request.

## Properties

| Property                                                    | Type     | Description                                                                                                                                                          |
| ----------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `idToken?`                             | `string` | ID token hint identifying the session to terminate. When provided, the authorization server can use this value to determine which user session should be signed out. |
| `postLogoutRedirectUri?` | `string` | The URL the authorization server should redirect the user to after a successful sign-out.                                                                            |
| `state?`                                 | `string` | Optional state value returned to the application after sign-out.                                                                                                     |
