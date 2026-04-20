---
rootSdk: Node.js Backend
title: "Jwk"
category: Types
framework: Express
---

# Type: Jwk

Represents a JSON Web Key (JWK) as defined by RFC 7517.

A JWK describes a cryptographic key used to verify or encrypt JSON Web Tokens (JWTs) as obtained from the JWKS (JSON Web Key Set) endpoint exposed by the authorization server.

The available properties depend on the key type (`kty`).

## alg?

> `optional` **alg**: `string`

Intended algorithm for the key (for example: `RS256`).

---

## crv?

> `optional` **crv**: `string`

Elliptic curve name (for example: `P-256`).

---

## d?

> `optional` **d**: `string`

RSA private exponent.

---

## dp?

> `optional` **dp**: `string`

RSA first factor CRT exponent.

---

## dq?

> `optional` **dq**: `string`

RSA second factor CRT exponent.

---

## e?

> `optional` **e**: `string`

RSA public exponent.

---

## ext?

> `optional` **ext**: `boolean`

Indicates whether the key is extractable.

---

## k?

> `optional` **k**: `string`

Symmetric key value (base64url encoded).

---

## key_ops?

> `optional` **key_ops**: `string`[]

Allowed operations for the key (e.g. `sign`, `verify`, `encrypt`).

---

## kid?

> `optional` **kid**: `string`

Key identifier used to match keys during verification.

---

## kty

> **kty**: `string`

Key type (for example: `RSA`, or `EC`).

---

## n?

> `optional` **n**: `string`

RSA modulus.

---

## oth?

> `optional` **oth**: \{ `d?`: `string`; `r?`: `string`; `t?`: `string`; \}[]

Additional prime information (multi-prime RSA).

| Name | Type     |
| ---- | -------- |
| `d?` | `string` |
| `r?` | `string` |
| `t?` | `string` |

---

## p?

> `optional` **p**: `string`

RSA first prime factor.

---

## q?

> `optional` **q**: `string`

RSA second prime factor.

---

## qi?

> `optional` **qi**: `string`

RSA CRT coefficient.

---

## use?

> `optional` **use**: `string`

Public key use (`sig` for signature or `enc` for encryption).

---

## x?

> `optional` **x**: `string`

X coordinate for EC public keys.

---

## x5c?

> `optional` **x5c**: `string`[]

X.509 certificate chain.

---

## x5t?

> `optional` **x5t**: `string`

X.509 certificate SHA-1 thumbprint.

---

## x5t#S256?

> `optional` **x5t#S256**: `string`

X.509 certificate SHA-256 thumbprint.

---

## x5u?

> `optional` **x5u**: `string`

URL referencing the X.509 certificate.

---

## y?

> `optional` **y**: `string`

Y coordinate for EC public keys.
