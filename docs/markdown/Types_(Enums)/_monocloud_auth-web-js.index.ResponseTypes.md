---
rootSdk: JavaScript
title: "ResponseTypes"
category: Enums
description: "Supported OAuth 2.0 / OpenID Connect response types."
---

# Enum: ResponseTypes

> **ResponseTypes** = `"code"` \| `"token"` \| `"id_token"` \| `"id_token token"` \| `"code id_token"` \| `"code token"` \| `"code id_token token"`

Supported OAuth 2.0 / OpenID Connect response types.

Response types determine which artifacts are returned from the authorization endpoint during authentication.

> Modern applications should prefer the Authorization Code Flow (`code`) with PKCE. Implicit flow variants are included for compatibility with legacy or specialized scenarios.

## Type Declaration

- `code` - Authorization Code Flow (recommended). Returns an authorization code that is exchanged for tokens on the server-side.
- `token` - Implicit Flow returning an access token directly from the authorization endpoint.
- `id_token` - Implicit Flow returning an ID token.
- `id_token token` - Implicit Flow returning both an ID token and an access token.
- `code id_token` - Hybrid Flow returning an authorization code and an ID token.
- `code token` - Hybrid Flow returning an authorization code and an access token.
- `code id_token token` - Hybrid Flow returning an authorization code, ID token, and access token.
