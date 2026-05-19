---
rootSdk: Node.js
title: "RefetchUserInfoOptions"
category: Types
description: "Options used when refetching user profile data from the UserInfo endpoint."
---

# Type: RefetchUserInfoOptions

Options used when refetching user profile data from the UserInfo endpoint.

## Properties

| Property                                            | Type                                                                                        | Description                                                                                                                |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `onSessionCreating?` | [`OnSessionCreating`](/sdks/nodejs/api-reference/handler-types/onsessioncreating) | Callback invoked before a session is created or updated. Allows customization or enrichment of the session.                |
| `strictProfileSync?` | `boolean`                                                                                   | When enabled, replaces the existing session user profile with a new profile constructed from the latest UserInfo response. |
