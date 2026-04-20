---
rootSdk: Node.js Backend
title: "IssuerMetadata"
category: Types
framework: Fastify
---

# Type: IssuerMetadata

OpenID Connect Discovery metadata published by the authorization server.

## authorization_endpoint

> **authorization_endpoint**: `string`

Authorization endpoint used to initiate authentication requests.

---

## backchannel_logout_session_supported

> **backchannel_logout_session_supported**: `boolean`

Indicates back-channel logout session support.

---

## backchannel_logout_supported

> **backchannel_logout_supported**: `boolean`

Indicates support for back-channel logout.

---

## check_session_iframe

> **check_session_iframe**: `string`

Session management iframe endpoint.

---

## claims_supported

> **claims_supported**: `string`[]

Claims that may be returned in tokens or UserInfo responses.

---

## code_challenge_methods_supported

> **code_challenge_methods_supported**: `string`[]

Supported PKCE code challenge methods.

---

## device_authorization_endpoint

> **device_authorization_endpoint**: `string`

Device Authorization Grant endpoint.

---

## end_session_endpoint

> **end_session_endpoint**: `string`

End-session endpoint used to initiate logout.

---

## frontchannel_logout_session_supported

> **frontchannel_logout_session_supported**: `boolean`

Indicates front-channel logout session support.

---

## frontchannel_logout_supported

> **frontchannel_logout_supported**: `boolean`

Indicates support for front-channel logout.

---

## grant_types_supported

> **grant_types_supported**: `string`[]

Supported OAuth grant types.

---

## id_token_signing_alg_values_supported

> **id_token_signing_alg_values_supported**: `string`[]

Supported signing algorithms for ID tokens.

---

## introspection_endpoint

> **introspection_endpoint**: `string`

Token introspection endpoint.

---

## issuer

> **issuer**: `string`

The issuer identifier for the authorization server.

---

## jwks_uri

> **jwks_uri**: `string`

JSON Web Key Set (JWKS) endpoint used to obtain signing keys.

---

## pushed_authorization_request_endpoint?

> `optional` **pushed_authorization_request_endpoint**: `string`

Pushed Authorization Request (PAR) endpoint.

---

## request_object_signing_alg_values_supported

> **request_object_signing_alg_values_supported**: `string`[]

Supported signing algorithms for request objects.

---

## request_parameter_supported

> **request_parameter_supported**: `boolean`

Indicates support for request objects passed by value.

---

## request_uri_parameter_supported

> **request_uri_parameter_supported**: `boolean`

Indicates support for request objects passed by reference (request_uri).

---

## require_pushed_authorization_requests

> **require_pushed_authorization_requests**: `boolean`

Indicates whether PAR is required for authorization requests.

---

## response_modes_supported

> **response_modes_supported**: `string`[]

Supported response modes.

---

## response_types_supported

> **response_types_supported**: `string`[]

Supported OAuth/OIDC response types.

---

## revocation_endpoint

> **revocation_endpoint**: `string`

Token revocation endpoint.

---

## scopes_supported

> **scopes_supported**: `string`[]

OAuth scopes supported by the authorization server.

---

## subject_types_supported

> **subject_types_supported**: `string`[]

Supported subject identifier types.

---

## token_endpoint

> **token_endpoint**: `string`

Token endpoint used to exchange authorization codes for tokens.

---

## token_endpoint_auth_methods_supported

> **token_endpoint_auth_methods_supported**: `string`[]

Supported authentication methods for the token endpoint.

---

## userinfo_endpoint

> **userinfo_endpoint**: `string`

UserInfo endpoint used to retrieve user profile claims.
