---
rootSdk: Node.js Backend
title: "MonoCloudTokenErrorCode"
category: Enums
framework: Fastify
description: "Machine-readable code identifying why a token operation failed."
---

# Enum: MonoCloudTokenErrorCode

> **MonoCloudTokenErrorCode** = `"invalid_token"` \| `"insufficient_scope"` \| `"insufficient_groups"`

Machine-readable code identifying why a token operation failed.

## Type Declaration

- `invalid_token` - The token is missing, malformed, expired, revoked, or otherwise failed validation.
- `insufficient_scope` - The token does not contain the scopes required for the request.
- `insufficient_groups` - The token's subject is not a member of the groups required for the request.
