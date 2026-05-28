---
rootSdk: JavaScript
title: "CodeChallengeMethod"
category: Enums
description: "Supported PKCE (Proof Key for Code Exchange) code challenge methods."
---

# Enum: CodeChallengeMethod

> **CodeChallengeMethod** = `"plain"` \| `"S256"`

Supported PKCE (Proof Key for Code Exchange) code challenge methods.

PKCE protects authorization code flows by binding the authorization request to the token exchange using a cryptographic verifier.

## Type Declaration

- `plain` - Uses the code verifier directly as the challenge. Not recommended for production use.
- `S256` - Uses a SHA-256 hash of the code verifier.
