---
rootSdk: Node.js
title: "ValidateJwtAccessTokenOptions"
category: Types
---

# Type: ValidateJwtAccessTokenOptions

Options for validating a JWT access token.

## Extends

- [`TokenValidationOptionsBase`](/sdks/nodejs/api-reference/types/tokenvalidationoptionsbase)

## Properties

| Property                                                              | Type                                         | Description                                                                                         |
| --------------------------------------------------------------------- | -------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `clientCertificate?`                   | `string`                                     | PEM-encoded client certificate used for certificate-bound token validation.                         |
| `groups?`                                         | `string`[]                                   | List of group names or identifiers that must be present in the token's groups claim.                |
| `jwks?`                                             | [`Jwks`](/sdks/nodejs/api-reference/types/jwks) | Pre-fetched JSON Web Key Set to use for signature verification instead of fetching from the server. |
| `scopes?`                                         | `string`[]                                   | List of scopes that must all be present in the token's `scope` claim.                               |
| `validateCertificateBinding?` | `boolean`                                    | When `true`, validates certificate binding for certificate-bound access tokens.                     |
