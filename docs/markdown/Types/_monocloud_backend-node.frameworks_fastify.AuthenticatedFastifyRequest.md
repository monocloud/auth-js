---
rootSdk: Node.js Backend
title: "AuthenticatedFastifyRequest"
category: Types
framework: Fastify
---

# Type: AuthenticatedFastifyRequest

> **AuthenticatedFastifyRequest** = `FastifyRequest` & \{ `claims`: [`AccessTokenClaims`](/sdks/fastify-backend/api-reference/types/accesstokenclaims); \}

A Fastify request augmented with validated access token claims.

## Type Declaration

| Name     | Type                                                                      | Description                                                               |
| -------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `claims` | [`AccessTokenClaims`](/sdks/fastify-backend/api-reference/types/accesstokenclaims) | Validated access token claims attached after successful token validation. |
