---
rootSdk: JavaScript
title: "ClientAuthMethod"
category: Enums
description: "Supported OAuth 2.0 client authentication methods. These methods define how a client authenticates itself when calling the authorization server token endpoint."
---

# Enum: ClientAuthMethod

> **ClientAuthMethod** = `"client_secret_basic"` \| `"client_secret_post"` \| `"client_secret_jwt"` \| `"private_key_jwt"` \| `"tls_client_auth"` \| `"self_signed_tls_client_auth"`

Supported OAuth 2.0 client authentication methods.

These methods define how a client authenticates itself when calling the authorization server token endpoint.

## Type Declaration

- `client_secret_basic` - Client credentials are sent using HTTP Basic authentication
- `client_secret_post` - Client credentials are included in the request body as form parameters.
- `client_secret_jwt` - Client authenticates using a signed JWT created with the client secret.
- `private_key_jwt` - Client authenticates using a signed JWT created with a private key.
- `tls_client_auth` - Client authenticates using a TLS client certificate issued by a trusted certificate authority.
- `self_signed_tls_client_auth` - Client authenticates using a self-signed TLS client certificate.
