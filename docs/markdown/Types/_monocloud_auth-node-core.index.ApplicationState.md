---
rootSdk: Node.js Core
title: "ApplicationState"
category: Types
description: "Represents custom application state associated with an authentication request."
---

# Type: ApplicationState

Represents custom application state associated with an authentication request.

This object is populated via `onSetApplicationState` and is persisted through the authentication flow. The resolved value is later available during session creation and can be used to carry application-specific context (for example: return targets, workflow state, or tenant hints).

## Extends

- `Record`\<`string`, `any`\>

## Indexable

\[`key`: `string`\]: `any`
