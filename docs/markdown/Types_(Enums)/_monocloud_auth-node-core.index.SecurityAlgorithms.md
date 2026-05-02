---
rootSdk: Node.js Core
title: "SecurityAlgorithms"
category: Enums
description: "Supported JSON Web Signature (JWS) algorithms used to sign tokens."
---

# Enum: SecurityAlgorithms

> **SecurityAlgorithms** = `"RS256"` \| `"RS384"` \| `"RS512"` \| `"PS256"` \| `"PS384"` \| `"PS512"` \| `"ES256"` \| `"ES384"` \| `"ES512"`

Supported JSON Web Signature (JWS) algorithms used to sign tokens.

These algorithms define how tokens issued by MonoCloud are cryptographically signed and verified. The expected algorithm should match the configuration of your MonoCloud application.

## Type Declaration

- `RS256` - RSA using SHA-256. Default and most commonly used signing algorithm.
- `RS384` - RSA using SHA-384.
- `RS512` - RSA using SHA-512.
- `PS256` - RSA-PSS using SHA-256. Provides stronger cryptographic padding than RS256.
- `PS384` - RSA-PSS using SHA-384.
- `PS512` - RSA-PSS using SHA-512.
- `ES256` - ECDSA using P-256 curve and SHA-256. Produces smaller tokens and faster verification.
- `ES384` - ECDSA using P-384 curve and SHA-384.
- `ES512` - ECDSA using P-521 curve and SHA-512.
