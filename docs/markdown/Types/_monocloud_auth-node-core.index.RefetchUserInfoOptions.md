---
rootSdk: Node.js Core
title: "RefetchUserInfoOptions"
category: Types
description: "Options used when refetching user profile data from the UserInfo endpoint."
---

# Type: RefetchUserInfoOptions

Options used when refetching user profile data from the UserInfo endpoint.

## Properties

| Property                                            | Type                                                                                                     | Description                                                                                                                |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `onSessionCreating?` | [`OnCoreSessionCreating`](/sdks/nodejs-core/api-reference/handler-types/oncoresessioncreating) | Callback invoked before a session is created or updated. Allows customization or enrichment of the session.                |
| `strictProfileSync?` | `boolean`                                                                                                | When enabled, replaces the existing session user profile with a new profile constructed from the latest UserInfo response. |
