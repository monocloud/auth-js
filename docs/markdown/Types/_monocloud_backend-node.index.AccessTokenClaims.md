---
rootSdk: Node.js Backend
title: "AccessTokenClaims"
category: Types
---

# Type: AccessTokenClaims

Claims contained in a validated OAuth 2.0 access token.

## Extends

- [`JwtClaims`](/sdks/nodejs-backend/api-reference/types/jwtclaims)

## Indexable

\[`key`: `string`\]: `unknown`

Additional custom or provider-specific claims.

## Properties

| Property                            | Type                   | Description                                                         |
| ----------------------------------- | ---------------------- | ------------------------------------------------------------------- |
| `aud`              | `string` \| `string`[] | Intended audience(s) of the token.                                  |
| `client_id?` | `string`               | Client ID of the application the token was issued to.               |
| `exp`              | `number`               | Expiration time of the token (Unix epoch seconds).                  |
| `iat`              | `number`               | Time at which the token was issued (Unix epoch seconds).            |
| `iss`              | `string`               | Issuer identifier - the authorization server that issued the token. |
| `jti?`             | `string`               | JWT ID (unique identifier for the token).                           |
| `nbf?`             | `number`               | Not-before time (Unix epoch seconds).                               |
| `scope?`         | `string`               | OAuth scope associated with the token.                              |
| `sub`              | `string`               | Subject identifier — uniquely identifies the authenticated user.    |
