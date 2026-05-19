---
rootSdk: Node.js Backend
title: "JwtClaims"
category: Types
framework: Fastify
description: "Standard JWT claims shared between ID tokens and access tokens."
---

# Type: JwtClaims

Standard JWT claims shared between ID tokens and access tokens.

## Indexable

\[`key`: `string`\]: `unknown`

Additional custom or provider-specific claims.

## aud

> **aud**: `string` \| `string`[]

Intended audience(s) of the token.

---

## exp

> **exp**: `number`

Expiration time of the token (Unix epoch seconds).

---

## iat

> **iat**: `number`

Time at which the token was issued (Unix epoch seconds).

---

## iss

> **iss**: `string`

Issuer identifier - the authorization server that issued the token.

---

## nbf?

> `optional` **nbf**: `number`

Not-before time (Unix epoch seconds).

---

## sub

> **sub**: `string`

Subject identifier — uniquely identifies the authenticated user.
