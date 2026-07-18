---
rootSdk: Node.js Core
title: "DisplayOptions"
category: Enums
description: "Supported OpenID Connect display parameter values."
---

# Enum: DisplayOptions

> **DisplayOptions** = `"page"` \| `"popup"` \| `"touch"` \| `"wap"` \| `string`

Supported OpenID Connect `display` parameter values.

The display parameter hints to the authorization server how the authentication or consent UI should be presented to the user.

## Type Declaration

- `page` - Full-page authentication experience in the browser.
- `popup` - Authentication optimized for popup windows.
- `touch` - Authentication optimized for touch-based devices.
- `wap` - Authentication optimized for legacy mobile or constrained browsers.
- `string` - Any other display value supported by the authorization server.
