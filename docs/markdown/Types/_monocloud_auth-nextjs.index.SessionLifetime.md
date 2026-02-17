---
rootSdk: Next.js
title: "SessionLifetime"
category: Types
---

# Type: SessionLifetime

Represents the lifetime metadata associated with a user session.

The properties use short keys to minimize cookie and storage size, since this structure may be serialized as part of session data.

All timestamps are expressed as **Unix epoch time (seconds)**.

## Properties

| Property            | Type     | Description                                                                                                        |
| ------------------- | -------- | ------------------------------------------------------------------------------------------------------------------ |
| `c`  | `number` | Session creation time. The moment the session was initially established.                                           |
| `e?` | `number` | Optional expiration time.                                                                                          |
| `u`  | `number` | Last updated time. Updated whenever the session is refreshed or extended (for example, during sliding expiration). |
