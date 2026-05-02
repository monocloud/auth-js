---
rootSdk: Node.js
title: "Jwks"
category: Types
description: "Represents a JSON Web Key Set (JWKS). A JWKS is a collection of public JSON Web Keys used to verify signatures of JSON Web Tokens (JWTs)."
---

# Type: Jwks

Represents a JSON Web Key Set (JWKS).

A JWKS is a collection of public JSON Web Keys used to verify signatures of JSON Web Tokens (JWTs).

## Properties

| Property                 | Type                                         | Description                                        |
| ------------------------ | -------------------------------------------- | -------------------------------------------------- |
| `keys` | [`Jwk`](/sdks/nodejs/api-reference/types/jwk)[] | The list of public keys contained in this key set. |
