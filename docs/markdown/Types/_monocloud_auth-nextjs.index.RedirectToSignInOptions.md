---
rootSdk: Next.js
title: "RedirectToSignInOptions"
category: Types
description: "Options for redirectToSignIn()."
---

# Type: RedirectToSignInOptions

Options for [redirectToSignIn()](/sdks/nextjs/api-reference/functions/redirecttosignin).

## Extends

- [`ExtraAuthParams`](/sdks/nextjs/api-reference/types/extraauthparams)

## Properties

| Property                                            | Type                                                                                  | Description                                                                                                                     |
| --------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `acrValues?`                 | `string`[]                                                                            | Authentication Context Class Reference (ACR) values requesting specific authentication assurance levels or methods.             |
| `authenticatorHint?` | [`Authenticators`](/sdks/nextjs/api-reference/enums/authenticators) | Hint to the authorization server indicating which authenticator or connection should be used.                                   |
| `display?`                     | [`DisplayOptions`](/sdks/nextjs/api-reference/enums/displayoptions) | Preferred display mode for the authentication UI.                                                                               |
| `loginHint?`                 | `string`                                                                              | Hint identifying the user (for example, email or username). Used to prefill or optimize the sign-in experience.                 |
| `maxAge?`                       | `number`                                                                              | Maximum acceptable time (in seconds) since the user last authenticated. If exceeded, the user may be required to sign in again. |
| `prompt?`                       | [`Prompt`](/sdks/nextjs/api-reference/enums/prompt)                 | Controls authentication interaction behavior. For example, forcing login or consent.                                            |
| `resource?`                   | `string`                                                                              | Space-separated list of resource indicators that scope the issued access token.                                                 |
| `returnUrl?`                 | `string`                                                                              | URL to return the user to after successful authentication. Must be a relative application URL.                                  |
| `scopes?`                       | `string`                                                                              | Space-separated list of scopes requested during authentication.                                                                 |
| `uiLocales?`                 | `string`                                                                              | Preferred UI language.                                                                                                          |
