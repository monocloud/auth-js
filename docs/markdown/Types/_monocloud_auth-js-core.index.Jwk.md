---
rootSdk: js-core
title: "Jwk"
category: Types
---

# Type: Jwk

Represents a JSON Web Key (JWK) as defined by RFC 7517.

A JWK describes a cryptographic key used to verify or encrypt JSON Web Tokens (JWTs) as obtained from the JWKS (JSON Web Key Set) endpoint exposed by the authorization server.

The available properties depend on the key type (`kty`).

## Properties

| Property                         | Type                                                    | Description                                                        |
| -------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------ |
| `alg?`          | `string`                                                | Intended algorithm for the key (for example: `RS256`).             |
| `crv?`          | `string`                                                | Elliptic curve name (for example: `P-256`).                        |
| `d?`              | `string`                                                | RSA private exponent.                                              |
| `dp?`            | `string`                                                | RSA first factor CRT exponent.                                     |
| `dq?`            | `string`                                                | RSA second factor CRT exponent.                                    |
| `e?`              | `string`                                                | RSA public exponent.                                               |
| `ext?`          | `boolean`                                               | Indicates whether the key is extractable.                          |
| `k?`              | `string`                                                | Symmetric key value (base64url encoded).                           |
| `key_ops?`  | `string`[]                                              | Allowed operations for the key (e.g. `sign`, `verify`, `encrypt`). |
| `kid?`          | `string`                                                | Key identifier used to match keys during verification.             |
| `kty`           | `string`                                                | Key type (for example: `RSA`, or `EC`).                            |
| `n?`              | `string`                                                | RSA modulus.                                                       |
| `oth?`          | \{ `d?`: `string`; `r?`: `string`; `t?`: `string`; \}[] | Additional prime information (multi-prime RSA).                    |
| `p?`              | `string`                                                | RSA first prime factor.                                            |
| `q?`              | `string`                                                | RSA second prime factor.                                           |
| `qi?`            | `string`                                                | RSA CRT coefficient.                                               |
| `use?`          | `string`                                                | Public key use (`sig` for signature or `enc` for encryption).      |
| `x?`              | `string`                                                | X coordinate for EC public keys.                                   |
| `x5c?`          | `string`[]                                              | X.509 certificate chain.                                           |
| `x5t?`          | `string`                                                | X.509 certificate SHA-1 thumbprint.                                |
| `x5t#S256?` | `string`                                                | X.509 certificate SHA-256 thumbprint.                              |
| `x5u?`          | `string`                                                | URL referencing the X.509 certificate.                             |
| `y?`              | `string`                                                | Y coordinate for EC public keys.                                   |
