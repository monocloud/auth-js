---
rootSdk: Node.js Backend
title: "JwsHeaderParameters"
category: Types
framework: Fastify
---

# Type: JwsHeaderParameters

Parameters contained in a JSON Web Signature (JWS) header.

## alg

> **alg**: [`SecurityAlgorithms`](/sdks/nodejs/api-reference/enums/securityalgorithms)

The cryptographic algorithm used to sign the token.

---

## crit?

> `optional` **crit**: `string`[]

List of header parameters that are marked as critical and must be understood by the token processor.

---

## jwk?

> `optional` **jwk**: [`Jwk`](/sdks/fastify-backend/api-reference/types/jwk)

An embedded JSON Web Key (JWK) containing the signing key.

---

## kid?

> `optional` **kid**: `string`

Identifier of the key used to sign the token.

---

## typ?

> `optional` **typ**: `string`

The token type.
