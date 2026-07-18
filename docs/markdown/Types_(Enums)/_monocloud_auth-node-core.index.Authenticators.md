---
rootSdk: Node.js Core
title: "Authenticators"
category: Enums
description: "Supported authentication methods and identity providers."
---

# Enum: Authenticators

> **Authenticators** = `"password"` \| `"passkey"` \| `"email"` \| `"phone"` \| `string`

Supported authentication methods and identity providers.

## Type Declaration

- `password` - Username/password authentication.
- `passkey` - Passkey (WebAuthn / FIDO2) authentication.
- `email` - Email-based authentication (magic link or OTP).
- `phone` - Phone-based authentication (SMS OTP).
- `string` - Any other authenticator or identity provider configured for your MonoCloud
  application (for example a social or enterprise connection), identified by
  its name.
