---
rootSdk: Next.js
title: "MonoCloudStateOptions"
category: Types
description: "Configuration options for authentication state handling."
---

# Type: MonoCloudStateOptions

Configuration options for authentication state handling.

## Properties

| Property                                   | Type                                                                                         | Description                                                                                                                                                                                                                                                                                   |
| ------------------------------------------ | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cookie`               | [`MonoCloudStateCookieOptions`](/sdks/nextjs/api-reference/types/monocloudstatecookieoptions) | Configuration for the state cookie. This cookie temporarily stores authorization transaction data required to validate the callback response and prevent replay or CSRF attacks.                                                                                                              |
| `duration`           | `number`                                                                                     | The lifetime of an authorization transaction in seconds.                                                                                                                                                                                                                                      |
| `maxConcurrent` | `number`                                                                                     | The maximum number of concurrent sign-in transactions retained. When a new sign in would exceed the limit, the earliest pending transactions are evicted first. Set to `1` for sequential sign-ins, where starting a new sign in discards the previous pending one. Must be between 1 and 20. |
