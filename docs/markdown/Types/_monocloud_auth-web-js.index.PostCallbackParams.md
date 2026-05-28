---
rootSdk: JavaScript
title: "PostCallbackParams"
category: Types
description: "Metadata passed to PostCallback after callback processing completes."
---

# Type: PostCallbackParams

> **PostCallbackParams** = \{ `mode`: [`InteractionMode`](/sdks/web-js/api-reference/enums/interactionmode) \| `"silent"`; `returnUrl?`: `string`; `type`: `"signIn"`; \} \| \{ `mode`: [`InteractionMode`](/sdks/web-js/api-reference/enums/interactionmode); `returnUrl?`: `string`; `type`: `"signOut"`; \}

Metadata passed to [PostCallback](/sdks/web-js/api-reference/handler-types/postcallback) after callback processing completes.

## Type Declaration

> \{ `mode`: [`InteractionMode`](/sdks/web-js/api-reference/enums/interactionmode) \| `"silent"`; `returnUrl?`: `string`; `type`: `"signIn"`; \}

| Name         | Type                                                                                                  | Description                                |
| ------------ | ----------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `mode`       | [`InteractionMode`](/sdks/web-js/api-reference/enums/interactionmode) \| `"silent"` | Interaction mode used during sign-in.      |
| `returnUrl?` | `string`                                                                                              | Optional URL to navigate to after sign-in. |
| `type`       | `"signIn"`                                                                                            | Indicates a sign-in flow was completed.    |


> \{ `mode`: [`InteractionMode`](/sdks/web-js/api-reference/enums/interactionmode); `returnUrl?`: `string`; `type`: `"signOut"`; \}

| Name         | Type                                                                                    | Description                                 |
| ------------ | --------------------------------------------------------------------------------------- | ------------------------------------------- |
| `mode`       | [`InteractionMode`](/sdks/web-js/api-reference/enums/interactionmode) | Interaction mode used during sign-out.      |
| `returnUrl?` | `string`                                                                                | Optional URL to navigate to after sign-out. |
| `type`       | `"signOut"`                                                                             | Indicates a sign-out flow was completed.    |
