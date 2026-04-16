---
rootSdk: Node.js Backend
title: "ProtectOptions"
category: Types
---

# Type: ProtectOptions

Options for protecting APIs.

## Extends

- `Omit`\<[`ValidateAccessTokenOptions`](/sdks/nodejs-backend/api-reference/types/validateaccesstokenoptions), `"clientCertificate"`\>

## Properties

| Property                                                              | Type       | Description                                                                          |
| --------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------ |
| `groups?`                                         | `string`[] | List of group names or identifiers that must be present in the token's groups claim. |
| `scopes?`                                         | `string`[] | List of scopes that must all be present in the token's `scope` claim.                |
| `validateCertificateBinding?` | `boolean`  | When `true`, validates certificate binding for certificate-bound access tokens.      |
