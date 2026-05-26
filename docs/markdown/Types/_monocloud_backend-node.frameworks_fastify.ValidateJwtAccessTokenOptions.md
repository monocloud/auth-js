---
rootSdk: Node.js Backend
title: "ValidateJwtAccessTokenOptions"
category: Types
framework: Fastify
description: "Options for validating a JWT access token."
---

# Type: ValidateJwtAccessTokenOptions

Options for validating a JWT access token.

## Extends

- [`TokenValidationOptionsBase`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase)

## clientCertificate
> `optional` **clientCertificate**: `string`

PEM-encoded client certificate used for certificate-bound token validation.

### Inherited from

[`TokenValidationOptionsBase`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase).[`clientCertificate`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase#clientcertificate)

---

## groups
> `optional` **groups**: `string`[]

List of group names or identifiers that must be present in the token's groups claim.

### Inherited from

[`TokenValidationOptionsBase`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase).[`groups`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase#groups)

---

## jwks
> `optional` **jwks**: [`Jwks`](/sdks/fastify-backend/api-reference/types/jwks)

Pre-fetched JSON Web Key Set to use for signature verification instead of fetching from the server.

---

## scopes
> `optional` **scopes**: `string`[]

List of scopes that must all be present in the token's `scope` claim.

### Inherited from

[`TokenValidationOptionsBase`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase).[`scopes`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase#scopes)

---

## validateCertificateBinding
> `optional` **validateCertificateBinding**: `boolean`

When `true`, validates certificate binding for certificate-bound access tokens.

### Default Value

```ts
false;
```

### Inherited from

[`TokenValidationOptionsBase`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase).[`validateCertificateBinding`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase#validatecertificatebinding)
