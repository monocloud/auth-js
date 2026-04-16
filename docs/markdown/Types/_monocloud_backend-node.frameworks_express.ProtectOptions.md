---
rootSdk: Node.js Backend
title: "ProtectOptions"
category: Types
framework: Express
---

# Type: ProtectOptions

Options for protecting APIs.

## Extends

- `Omit`\<[`ValidateAccessTokenOptions`](/sdks/express-backend/api-reference/types/validateaccesstokenoptions), `"clientCertificate"`\>

## groups?

> `optional` **groups**: `string`[]

List of group names or identifiers that must be present in the token's groups claim.

### Inherited from

[`ValidateAccessTokenOptions`](/sdks/express-backend/api-reference/types/validateaccesstokenoptions).[`groups`](/sdks/express-backend/api-reference/types/validateaccesstokenoptions#groups)

---

## scopes?

> `optional` **scopes**: `string`[]

List of scopes that must all be present in the token's `scope` claim.

### Inherited from

[`ValidateAccessTokenOptions`](/sdks/express-backend/api-reference/types/validateaccesstokenoptions).[`scopes`](/sdks/express-backend/api-reference/types/validateaccesstokenoptions#scopes)

---

## validateCertificateBinding?

> `optional` **validateCertificateBinding**: `boolean`

When `true`, validates certificate binding for certificate-bound access tokens.

### Default Value

```ts
false;
```

### Inherited from

[`ValidateAccessTokenOptions`](/sdks/express-backend/api-reference/types/validateaccesstokenoptions).[`validateCertificateBinding`](/sdks/express-backend/api-reference/types/validateaccesstokenoptions#validatecertificatebinding)
