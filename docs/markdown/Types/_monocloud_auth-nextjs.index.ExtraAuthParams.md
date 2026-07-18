---
rootSdk: Next.js
title: "ExtraAuthParams"
category: Types
description: "A subset of authorization parameters supported by client-side helpers."
---

# Type: ExtraAuthParams

A subset of authorization parameters supported by client-side helpers.

## Extends

- `Pick`\<[`AuthorizationParams`](/sdks/nextjs/api-reference/types/authorizationparams), `"scopes"` \| `"resource"` \| `"prompt"` \| `"display"` \| `"uiLocales"` \| `"acrValues"` \| `"authenticatorHint"` \| `"maxAge"` \| `"loginHint"` \| `"audience"` \| `"idTokenHint"`\>

## Properties

| Property                                            | Type                                                                                  | Description                                                                                                                     |
| --------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `acrValues?`                 | `string`[]                                                                            | Authentication Context Class Reference (ACR) values requesting specific authentication assurance levels or methods.             |
| `audience?`                   | `string`                                                                              | Identifies the target API (audience) that the issued access token is intended for.                                              |
| `authenticatorHint?` | [`Authenticators`](/sdks/nextjs/api-reference/enums/authenticators) | Hint to the authorization server indicating which authenticator or connection should be used.                                   |
| `display?`                     | [`DisplayOptions`](/sdks/nextjs/api-reference/enums/displayoptions) | Preferred display mode for the authentication UI.                                                                               |
| `idTokenHint?`             | `string`                                                                              | A previously issued ID token used as a hint about the user's current or past authenticated session.                             |
| `loginHint?`                 | `string`                                                                              | Hint identifying the user (for example, email or username). Used to prefill or optimize the sign-in experience.                 |
| `maxAge?`                       | `number`                                                                              | Maximum acceptable time (in seconds) since the user last authenticated. If exceeded, the user may be required to sign in again. |
| `prompt?`                       | [`Prompt`](/sdks/nextjs/api-reference/enums/prompt)                 | Controls authentication interaction behavior. For example, forcing login or consent.                                            |
| `resource?`                   | `string`                                                                              | Space-separated list of resource indicators that scope the issued access token.                                                 |
| `scopes?`                       | `string`                                                                              | Space-separated list of scopes requested during authentication.                                                                 |
| `uiLocales?`                 | `string`                                                                              | Preferred UI language.                                                                                                          |
