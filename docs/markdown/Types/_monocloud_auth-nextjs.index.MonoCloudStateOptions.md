---
rootSdk: Next.js
title: "MonoCloudStateOptions"
category: Types
---

# Type: MonoCloudStateOptions

Configuration options for authentication state handling.

## Properties

| Property                     | Type                                                                               | Description                                                                                                                                                                      |
| ---------------------------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cookie` | [`MonoCloudCookieOptions`](/sdks/nextjs/api-reference/types/monocloudcookieoptions) | Configuration for the state cookie. This cookie temporarily stores authorization transaction data required to validate the callback response and prevent replay or CSRF attacks. |
