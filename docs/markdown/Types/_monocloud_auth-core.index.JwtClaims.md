---
rootSdk: Node.js
title: "JwtClaims"
category: Types
---

# Type: JwtClaims

Standard JWT claims shared between ID tokens and access tokens.

## Indexable

\[`key`: `string`\]: `unknown`

Additional custom or provider-specific claims.

## Properties

| Property                | Type                   | Description                                                         |
| ----------------------- | ---------------------- | ------------------------------------------------------------------- |
| `aud`  | `string` \| `string`[] | Intended audience(s) of the token.                                  |
| `exp`  | `number`               | Expiration time of the token (Unix epoch seconds).                  |
| `iat`  | `number`               | Time at which the token was issued (Unix epoch seconds).            |
| `iss`  | `string`               | Issuer identifier - the authorization server that issued the token. |
| `jti?` | `string`               | JWT ID (unique identifier for the token).                           |
| `nbf?` | `number`               | Not-before time (Unix epoch seconds).                               |
| `sub`  | `string`               | Subject identifier — uniquely identifies the authenticated user.    |
