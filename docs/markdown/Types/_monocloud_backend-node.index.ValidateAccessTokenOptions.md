---
rootSdk: Node.js Backend
title: "ValidateAccessTokenOptions"
category: Types
---

# Type: ValidateAccessTokenOptions

Options for validating access tokens.

## Extends

- [`IntrospectOptions`](/sdks/nodejs-backend/api-reference/types/introspectoptions)

## Properties

| Property                                                              | Type       | Description                                                                          |
| --------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------ |
| `clientCertificate?`                   | `string`   | PEM-encoded client certificate used for certificate-bound token validation.          |
| `groups?`                                         | `string`[] | List of group names or identifiers that must be present in the token's groups claim. |
| `scopes?`                                         | `string`[] | List of scopes that must all be present in the token's `scope` claim.                |
| `validateCertificateBinding?` | `boolean`  | When `true`, validates certificate binding for certificate-bound access tokens.      |
