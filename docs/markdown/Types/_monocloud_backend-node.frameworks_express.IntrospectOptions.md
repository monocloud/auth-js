---
rootSdk: Node.js Backend
title: "IntrospectOptions"
category: Types
framework: Express
---

# Type: IntrospectOptions

Options for introspecting an opaque access token.

## Extends

- [`TokenValidationOptionsBase`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase)

## clientCertificate?

> `optional` **clientCertificate**: `string`

PEM-encoded client certificate used for certificate-bound token validation.

### Inherited from

[`TokenValidationOptionsBase`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase).[`clientCertificate`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase#clientcertificate)

---

## groups?

> `optional` **groups**: `string`[]

List of group names or identifiers that must be present in the token's groups claim.

### Inherited from

[`TokenValidationOptionsBase`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase).[`groups`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase#groups)

---

## scopes?

> `optional` **scopes**: `string`[]

List of scopes that must all be present in the token's `scope` claim.

### Inherited from

[`TokenValidationOptionsBase`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase).[`scopes`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase#scopes)

---

## validateCertificateBinding?

> `optional` **validateCertificateBinding**: `boolean`

When `true`, validates certificate binding for certificate-bound access tokens.

### Default Value

```ts
false;
```

### Inherited from

[`TokenValidationOptionsBase`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase).[`validateCertificateBinding`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase#validatecertificatebinding)
