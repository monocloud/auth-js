---
rootSdk: Node.js Core
title: "OnSetApplicationState"
category: Handler Types
description: "Callback invoked when the authentication state is being created before redirecting the user to the authorization server."
---

# Handler Type: OnSetApplicationState

> **OnSetApplicationState** = (`req`: [`MonoCloudRequest`](/sdks/nodejs-core/api-reference/types/monocloudrequest)) => `Promise`\<[`ApplicationState`](/sdks/nodejs-core/api-reference/types/applicationstate)\> \| [`ApplicationState`](/sdks/nodejs-core/api-reference/types/applicationstate)

Callback invoked when the authentication state is being created before redirecting the user to the authorization server.

Use this hook to attach custom application state that should survive the authentication round-trip and be available after the user returns from sign-in.

The returned value is stored securely and later provided during session creation.

Common use cases include:

- Preserving return URLs or navigation context
- Passing tenant or organization identifiers
- Storing temporary workflow state across authentication

## Parameters

| Parameter | Type                                                                               | Description                                     |
| --------- | ---------------------------------------------------------------------------------- | ----------------------------------------------- |
| `req`     | [`MonoCloudRequest`](/sdks/nodejs-core/api-reference/types/monocloudrequest) | The incoming request initiating authentication. |

## Returns

`Promise`\<[`ApplicationState`](/sdks/nodejs-core/api-reference/types/applicationstate)\> \| [`ApplicationState`](/sdks/nodejs-core/api-reference/types/applicationstate)

Returns an application state object, either synchronously or as a Promise.
