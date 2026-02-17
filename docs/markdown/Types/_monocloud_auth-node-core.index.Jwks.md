---
rootSdk: Node.js Core
title: "Jwks"
category: Types
---

# Type: Jwks

Represents a JSON Web Key Set (JWKS).

A JWKS is a collection of public JSON Web Keys used to verify signatures of JSON Web Tokens (JWTs).

## Properties

| Property                 | Type                                              | Description                                        |
| ------------------------ | ------------------------------------------------- | -------------------------------------------------- |
| `keys` | [`Jwk`](/sdks/nodejs-core/api-reference/types/jwk)[] | The list of public keys contained in this key set. |
