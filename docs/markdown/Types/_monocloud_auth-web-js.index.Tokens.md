---
rootSdk: JavaScript
title: "Tokens"
category: Types
description: "OAuth 2.0 / OpenID Connect token endpoint response."
---

# Type: Tokens

OAuth 2.0 / OpenID Connect token endpoint response.

## Properties

| Property                                    | Type     | Description                                                                                       |
| ------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------- |
| `access_token`    | `string` | Access token issued by the authorization server.                                                  |
| `expires_in?`       | `number` | Lifetime of the access token (in seconds) from the time the response was issued.                  |
| `id_token?`           | `string` | Optional ID token containing authentication claims about the user.                                |
| `refresh_token?` | `string` | Optional refresh token used to obtain new access tokens without requiring user re-authentication. |
| `scope?`                 | `string` | Space-separated list of scopes granted for the access token.                                      |
| `token_type?`       | `string` | Token type issued.                                                                                |
