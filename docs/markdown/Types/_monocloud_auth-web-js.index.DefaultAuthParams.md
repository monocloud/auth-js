---
rootSdk: JavaScript
title: "DefaultAuthParams"
category: Types
description: "Subset of AuthorizationParams that can be pre-configured as defaults for every authentication request."
---

# Type: DefaultAuthParams

> **DefaultAuthParams** = `Pick`\<[`AuthorizationParams`](/sdks/web-js/api-reference/types/authorizationparams), `"scopes"` \| `"resource"` \| `"responseType"` \| `"prompt"` \| `"display"` \| `"uiLocales"` \| `"acrValues"` \| `"maxAge"` \| `"loginHint"` \| `"authenticatorHint"` \| `"audience"` \| `"idTokenHint"`\>

Subset of [AuthorizationParams](/sdks/web-js/api-reference/types/authorizationparams) that can be pre-configured as defaults for every authentication request.

Per-request values (`state`, `nonce`, `codeChallenge`, `codeChallengeMethod`, `redirectUri`) are managed internally by the SDK and cannot be overridden here.
