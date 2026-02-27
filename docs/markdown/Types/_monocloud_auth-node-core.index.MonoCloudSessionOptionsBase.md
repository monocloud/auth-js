---
rootSdk: Node.js Core
title: "MonoCloudSessionOptionsBase"
category: Types
---

# Type: MonoCloudSessionOptionsBase

Configuration options for authentication sessions.

These options control how user sessions are created, persisted, and expired.

## Properties

| Property                                       | Type                                                                                  | Description                                                                                                                                                                                                                             |
| ---------------------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cookie`                   | [`MonoCloudCookieOptions`](/sdks/nodejs-core/api-reference/types/monocloudcookieoptions) | Configuration for the session cookie used to identify the user session.                                                                                                                                                                 |
| `duration`               | `number`                                                                              | The session lifetime in seconds. With **absolute sessions** (`sliding = false`), this defines the total session lifetime. With **sliding sessions**, this defines the idle timeout before the session expires.                          |
| `maximumDuration` | `number`                                                                              | The absolute maximum lifetime of a sliding session in seconds. This value limits how long a session can exist even if the user remains continuously active. Only applies when `sliding` is enabled.                                     |
| `sliding`                 | `boolean`                                                                             | Enables sliding session expiration. When enabled, the session expiration is extended on active requests, up to the configured `maximumDuration`. When disabled, the session expires after a fixed duration regardless of user activity. |
| `store?`                    | [`MonoCloudSessionStore`](/sdks/nodejs-core/api-reference/types/monocloudsessionstore)   | Optional session store used to persist session data. If not provided, The SDK uses the default cookie-based session storage. Custom stores allow centralized session management (e.g. Redis, database).                                 |
