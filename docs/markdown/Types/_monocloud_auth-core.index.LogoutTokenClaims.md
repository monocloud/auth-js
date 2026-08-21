---
rootSdk: Node.js
title: "LogoutTokenClaims"
category: Types
description: "Claims contained in a validated OpenID Connect Back-Channel Logout Token."
---

# Type: LogoutTokenClaims

Claims contained in a validated OpenID Connect Back-Channel Logout Token.

## Indexable

> \[`key`: `string`\]: `unknown`

Additional custom or provider-specific claims.

## Properties

| Property                     | Type                            | Description                                                         |
| ---------------------------- | ------------------------------- | ------------------------------------------------------------------- |
| `aud`       | `string` \| `string`[]          | Intended audience(s) of the token.                                  |
| `events` | `Record`\<`string`, `unknown`\> | Events claim declaring the JWT as a Logout Token.                   |
| `exp?`      | `number`                        | Expiration time of the token (Unix epoch seconds).                  |
| `iat`       | `number`                        | Time at which the token was issued (Unix epoch seconds).            |
| `iss`       | `string`                        | Issuer identifier - the authorization server that issued the token. |
| `jti?`      | `string`                        | Unique identifier of the token.                                     |
| `nbf?`      | `number`                        | Not-before time (Unix epoch seconds).                               |
| `sid?`      | `string`                        | Session identifier of the session being terminated.                 |
| `sub?`      | `string`                        | Subject identifier of the user whose sessions are being terminated. |
