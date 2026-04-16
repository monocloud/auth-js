---
rootSdk: Node.js Backend
title: "AccessTokenClaims"
category: Types
framework: Express
---

# Type: AccessTokenClaims

Claims contained in a validated OAuth 2.0 access token.

## Extends

- [`JwtClaims`](/sdks/express-backend/api-reference/types/jwtclaims)

## Indexable

\[`key`: `string`\]: `unknown`

Additional custom or provider-specific claims.

## aud

> **aud**: `string` \| `string`[]

Intended audience(s) of the token.

### Inherited from

[`JwtClaims`](/sdks/express-backend/api-reference/types/jwtclaims).[`aud`](/sdks/express-backend/api-reference/types/jwtclaims#aud)

---

## client_id?

> `optional` **client_id**: `string`

Client ID of the application the token was issued to.

---

## exp

> **exp**: `number`

Expiration time of the token (Unix epoch seconds).

### Inherited from

[`JwtClaims`](/sdks/express-backend/api-reference/types/jwtclaims).[`exp`](/sdks/express-backend/api-reference/types/jwtclaims#exp)

---

## iat

> **iat**: `number`

Time at which the token was issued (Unix epoch seconds).

### Inherited from

[`JwtClaims`](/sdks/express-backend/api-reference/types/jwtclaims).[`iat`](/sdks/express-backend/api-reference/types/jwtclaims#iat)

---

## iss

> **iss**: `string`

Issuer identifier - the authorization server that issued the token.

### Inherited from

[`JwtClaims`](/sdks/express-backend/api-reference/types/jwtclaims).[`iss`](/sdks/express-backend/api-reference/types/jwtclaims#iss)

---

## jti?

> `optional` **jti**: `string`

JWT ID (unique identifier for the token).

### Inherited from

[`JwtClaims`](/sdks/express-backend/api-reference/types/jwtclaims).[`jti`](/sdks/express-backend/api-reference/types/jwtclaims#jti)

---

## nbf?

> `optional` **nbf**: `number`

Not-before time (Unix epoch seconds).

### Inherited from

[`JwtClaims`](/sdks/express-backend/api-reference/types/jwtclaims).[`nbf`](/sdks/express-backend/api-reference/types/jwtclaims#nbf)

---

## scope?

> `optional` **scope**: `string`

OAuth scope associated with the token.

---

## sub

> **sub**: `string`

Subject identifier — uniquely identifies the authenticated user.

### Inherited from

[`JwtClaims`](/sdks/express-backend/api-reference/types/jwtclaims).[`sub`](/sdks/express-backend/api-reference/types/jwtclaims#sub)
