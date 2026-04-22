---
rootSdk: Node.js Backend
title: "protectApi"
category: Functions
framework: Express
---

# Function: protectApi

## Call Signature

> **protectApi**(`client`: [`MonoCloudBackendNodeClient`](/sdks/express-backend/api-reference/classes/monocloudbackendnodeclient), `options?`: [`ProtectApiRequestOptions`](/sdks/express-backend/api-reference/types/protectapirequestoptions)\<`Request`\<`ParamsDictionary`, `any`, `any`, `ParsedQs`, `Record`\<`string`, `any`\>\>\>): [`ProtectMiddleware`](/sdks/express-backend/api-reference/handler-types/protectmiddleware)

Creates an Express middleware factory for protecting API routes using a pre-configured client.

### Parameters

| Parameter  | Type                                                                                                                                                                                       | Description                                                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `client`   | [`MonoCloudBackendNodeClient`](/sdks/express-backend/api-reference/classes/monocloudbackendnodeclient)                                                                                     | A pre-configured [MonoCloudBackendNodeClient](/sdks/express-backend/api-reference/classes/monocloudbackendnodeclient) instance. |
| `options?` | [`ProtectApiRequestOptions`](/sdks/express-backend/api-reference/types/protectapirequestoptions)\<`Request`\<`ParamsDictionary`, `any`, `any`, `ParsedQs`, `Record`\<`string`, `any`\>\>\> | Options for extracting tokens and certificates from the request.                                                                |

### Returns

[`ProtectMiddleware`](/sdks/express-backend/api-reference/handler-types/protectmiddleware)

## Call Signature

> **protectApi**(`options?`: [`ProtectApiRequestOptions`](/sdks/express-backend/api-reference/types/protectapirequestoptions)\<`Request`\<`ParamsDictionary`, `any`, `any`, `ParsedQs`, `Record`\<`string`, `any`\>\>\>): [`ProtectMiddleware`](/sdks/express-backend/api-reference/handler-types/protectmiddleware)

Creates an Express middleware factory for protecting API routes.

A new [MonoCloudBackendNodeClient](/sdks/express-backend/api-reference/classes/monocloudbackendnodeclient) is created from the provided options,
or from environment variables.

### Parameters

| Parameter  | Type                                                                                                                                                                                       | Description                                                      |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- |
| `options?` | [`ProtectApiRequestOptions`](/sdks/express-backend/api-reference/types/protectapirequestoptions)\<`Request`\<`ParamsDictionary`, `any`, `any`, `ParsedQs`, `Record`\<`string`, `any`\>\>\> | Options for extracting tokens and certificates from the request. |

### Returns

[`ProtectMiddleware`](/sdks/express-backend/api-reference/handler-types/protectmiddleware)
