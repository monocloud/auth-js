---
rootSdk: JavaScript
title: "JwsHeaderParameters"
category: Types
description: "Parameters contained in a JSON Web Signature (JWS) header."
---

# Type: JwsHeaderParameters

Parameters contained in a JSON Web Signature (JWS) header.

## Properties

| Property                  | Type                                                                                          | Description                                                                                          |
| ------------------------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `alg`    | [`SecurityAlgorithms`](/sdks/web-js/api-reference/enums/securityalgorithms) | The cryptographic algorithm used to sign the token.                                                  |
| `crit?` | `string`[]                                                                                    | List of header parameters that are marked as critical and must be understood by the token processor. |
| `jwk?`   | [`Jwk`](/sdks/web-js/api-reference/types/jwk)                                                  | An embedded JSON Web Key (JWK) containing the signing key.                                           |
| `kid?`   | `string`                                                                                      | Identifier of the key used to sign the token.                                                        |
| `typ?`   | `string`                                                                                      | The token type.                                                                                      |
