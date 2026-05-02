---
rootSdk: Node.js Backend
title: "ValidateAccessTokenOptions"
category: Types
framework: Express
description: "Options for validating access tokens."
---

# Type: ValidateAccessTokenOptions

Options for validating access tokens.

## Extends

- [`IntrospectOptions`](/sdks/express-backend/api-reference/types/introspectoptions)

## clientCertificate?

> `optional` **clientCertificate**: `string`

PEM-encoded client certificate used for certificate-bound token validation.

### Inherited from

[`IntrospectOptions`](/sdks/express-backend/api-reference/types/introspectoptions).[`clientCertificate`](/sdks/express-backend/api-reference/types/introspectoptions#clientcertificate)

---

## groups?

> `optional` **groups**: `string`[]

List of group names or identifiers that must be present in the token's groups claim.

### Inherited from

[`IntrospectOptions`](/sdks/express-backend/api-reference/types/introspectoptions).[`groups`](/sdks/express-backend/api-reference/types/introspectoptions#groups)

---

## scopes?

> `optional` **scopes**: `string`[]

List of scopes that must all be present in the token's `scope` claim.

### Inherited from

[`IntrospectOptions`](/sdks/express-backend/api-reference/types/introspectoptions).[`scopes`](/sdks/express-backend/api-reference/types/introspectoptions#scopes)

---

## validateCertificateBinding?

> `optional` **validateCertificateBinding**: `boolean`

When `true`, validates certificate binding for certificate-bound access tokens.

### Default Value

```ts
false;
```

### Inherited from

[`IntrospectOptions`](/sdks/express-backend/api-reference/types/introspectoptions).[`validateCertificateBinding`](/sdks/express-backend/api-reference/types/introspectoptions#validatecertificatebinding)
