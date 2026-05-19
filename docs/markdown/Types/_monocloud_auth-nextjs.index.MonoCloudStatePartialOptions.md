---
rootSdk: Next.js
title: "MonoCloudStatePartialOptions"
category: Types
description: "Partial configuration options for authentication state handling."
---

# Type: MonoCloudStatePartialOptions

Partial configuration options for authentication state handling.

## Properties

| Property                      | Type                                                                                            | Description                                                                                                                                                                              |
| ----------------------------- | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cookie?` | `Partial`\<[`MonoCloudCookieOptions`](/sdks/nextjs/api-reference/types/monocloudcookieoptions)\> | Partial configuration for the state cookie. This cookie temporarily stores authorization transaction data required to validate the callback response and prevent replay or CSRF attacks. |
