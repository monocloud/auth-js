---
rootSdk: Node.js Core
title: "Prompt"
category: Enums
---

# Enum: Prompt

> **Prompt** = `"none"` \| `"login"` \| `"consent"` \| `"select_account"` \| `"create"`

Supported OpenID Connect `prompt` parameter values.

The `prompt` parameter controls whether the authorization server should force specific user interactions during authentication.

## Type Declaration

- `none` - Do not display any authentication or consent UI.
- `login` - Forces the user to re-authenticate even if an active session exists.
- `consent` - Forces the consent screen to be displayed to the user.
- `select_account` - Prompts the user to choose an account when multiple sessions exist.
- `create` - Prompts the user to create a new account (sign-up flow).
