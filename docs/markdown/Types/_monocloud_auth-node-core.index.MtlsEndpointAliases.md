---
rootSdk: Node.js Core
title: "MtlsEndpointAliases"
category: Types
description: "Alternate endpoint URLs that a client authenticating with mutual-TLS (mTLS) must use in place of the regular endpoints."
---

# Type: MtlsEndpointAliases

Alternate endpoint URLs that a client authenticating with mutual-TLS (mTLS) must use in
place of the regular endpoints.

## Properties

| Property                                                                                    | Type     | Description                                                     |
| ------------------------------------------------------------------------------------------- | -------- | --------------------------------------------------------------- |
| `device_authorization_endpoint?`                 | `string` | mTLS alias for the device authorization endpoint.               |
| `introspection_endpoint?`                               | `string` | mTLS alias for the token introspection endpoint.                |
| `pushed_authorization_request_endpoint?` | `string` | mTLS alias for the pushed authorization request (PAR) endpoint. |
| `revocation_endpoint?`                                     | `string` | mTLS alias for the token revocation endpoint.                   |
| `token_endpoint?`                                               | `string` | mTLS alias for the token endpoint.                              |
