---
rootSdk: Next.js
title: "MonoCloudStatePartialOptions"
category: Types
description: "Partial configuration options for authentication state handling."
---

# Type: MonoCloudStatePartialOptions

Partial configuration options for authentication state handling.

## Properties

| Property                                    | Type                                                                                                      | Description                                                                                                                                                                                                                                                                                   |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cookie?`               | `Partial`\<[`MonoCloudStateCookieOptions`](/sdks/nextjs/api-reference/types/monocloudstatecookieoptions)\> | Partial configuration for the state cookie. This cookie temporarily stores authorization transaction data required to validate the callback response and prevent replay or CSRF attacks.                                                                                                      |
| `duration?`           | `number`                                                                                                  | The lifetime of an authorization transaction in seconds.                                                                                                                                                                                                                                      |
| `maxConcurrent?` | `number`                                                                                                  | The maximum number of concurrent sign-in transactions retained. When a new sign in would exceed the limit, the earliest pending transactions are evicted first. Set to `1` for sequential sign-ins, where starting a new sign in discards the previous pending one. Must be between 1 and 20. |
