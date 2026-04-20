---
rootSdk: Node.js Backend
title: "AuthenticatedExpressRequest"
category: Types
framework: Express
---

# Type: AuthenticatedExpressRequest

> **AuthenticatedExpressRequest** = `Request` & \{ `user`: [`AccessTokenClaims`](/sdks/express-backend/api-reference/types/accesstokenclaims); \}

An Express request augmented with validated access token claims.

## Type Declaration

| Name   | Type                                                                      | Description                                                               |
| ------ | ------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `user` | [`AccessTokenClaims`](/sdks/express-backend/api-reference/types/accesstokenclaims) | Validated access token claims attached after successful token validation. |
