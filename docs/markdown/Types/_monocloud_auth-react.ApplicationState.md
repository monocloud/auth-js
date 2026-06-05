---
rootSdk: React
title: "ApplicationState"
category: Types
description: "Custom application state passed through an authentication flow."
---

# Type: ApplicationState

> **ApplicationState** = `Record`\<`string`, `unknown`\>

Custom application state passed through an authentication flow.

Captured when the flow is initiated (for example via `signIn` or `signInSilent`) and surfaced to the [OnSessionCreating](/sdks/react/api-reference/handler-types/onsessioncreating) hook when the session is constructed.
