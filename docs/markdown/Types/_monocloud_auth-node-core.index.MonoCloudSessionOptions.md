---
rootSdk: Node.js Core
title: "MonoCloudSessionOptions"
category: Types
---

# Type: MonoCloudSessionOptions

Partial configuration options for authentication sessions.

## Extends

- `Partial`\<`Omit`\<[`MonoCloudSessionOptionsBase`](/sdks/nodejs-core/api-reference/types/monocloudsessionoptionsbase), `"store"` \| `"cookie"`\>\>

## Properties

| Property                                        | Type                                                                                               | Description                                                                                                                                                                                                                             |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cookie?`                   | `Partial`\<[`MonoCloudCookieOptions`](/sdks/nodejs-core/api-reference/types/monocloudcookieoptions)\> | Session cookie settings.                                                                                                                                                                                                                |
| `duration?`               | `number`                                                                                           | The session lifetime in seconds. - With **absolute sessions** (`sliding = false`), this defines the total session lifetime. - With **sliding sessions**, this defines the idle timeout before the session expires.                      |
| `maximumDuration?` | `number`                                                                                           | The absolute maximum lifetime of a sliding session in seconds. This value limits how long a session can exist even if the user remains continuously active. Only applies when `sliding` is enabled.                                     |
| `sliding?`                 | `boolean`                                                                                          | Enables sliding session expiration. When enabled, the session expiration is extended on active requests, up to the configured `maximumDuration`. When disabled, the session expires after a fixed duration regardless of user activity. |
| `store?`                     | [`MonoCloudSessionStore`](/sdks/nodejs-core/api-reference/types/monocloudsessionstore)                | A custom session store implementation. When provided, sessions are persisted using this store instead of cookies-only storage.                                                                                                          |
