---
rootSdk: js-core
title: "PostCallbackParams"
category: Types
---

# Type: PostCallbackParams

> **PostCallbackParams** = \{ `mode`: [`InteractionMode`](/sdks/js-core/api-reference/enums/interactionmode) \| `"silent"`; `returnUrl?`: `string`; `type`: `"signIn"`; \} \| \{ `mode`: [`InteractionMode`](/sdks/js-core/api-reference/enums/interactionmode); `returnUrl?`: `string`; `type`: `"signOut"`; \}

Metadata passed to `PostCallback` after callback processing.
