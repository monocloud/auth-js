---
rootSdk: Node.js Backend
title: "protectApi"
category: Functions
framework: Express
---

# Function: protectApi

## Call Signature

> **protectApi**(`client`: [`MonoCloudBackendNodeClient`](/sdks/express-backend/api-reference/classes/monocloudbackendnodeclient), `requestOptions?`: [`ProtectApiRequestOptions`](/sdks/express-backend/api-reference/types/protectapirequestoptions)\<`Request`\<`ParamsDictionary`, `any`, `any`, `ParsedQs`, `Record`\<`string`, `any`\>\>\>): [`ProtectMiddleware`](/sdks/express-backend/api-reference/handler-types/protectmiddleware)

Creates an Express middleware factory for protecting API routes using a pre-configured client.

### Parameters

| Parameter         | Type                                                                                                                                                                                       | Description                                                                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `client`          | [`MonoCloudBackendNodeClient`](/sdks/express-backend/api-reference/classes/monocloudbackendnodeclient)                                                                                     | A pre-configured [MonoCloudBackendNodeClient](/sdks/express-backend/api-reference/classes/monocloudbackendnodeclient) instance. |
| `requestOptions?` | [`ProtectApiRequestOptions`](/sdks/express-backend/api-reference/types/protectapirequestoptions)\<`Request`\<`ParamsDictionary`, `any`, `any`, `ParsedQs`, `Record`\<`string`, `any`\>\>\> | Options for extracting tokens and certificates from the request.                                                                |

### Returns

[`ProtectMiddleware`](/sdks/express-backend/api-reference/handler-types/protectmiddleware)

## Call Signature

> **protectApi**(`options?`: `Partial`\<[`ProtectExpressApiOptions`](/sdks/express-backend/api-reference/types/protectexpressapioptions)\>): [`ProtectMiddleware`](/sdks/express-backend/api-reference/handler-types/protectmiddleware)

Creates an Express middleware factory for protecting API routes.

A new [MonoCloudBackendNodeClient](/sdks/express-backend/api-reference/classes/monocloudbackendnodeclient) is created from the provided options,
or from environment variables if no options are specified.

### Parameters

| Parameter  | Type                                                                                                                       | Description                               |
| ---------- | -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| `options?` | `Partial`\<[`ProtectExpressApiOptions`](/sdks/express-backend/api-reference/types/protectexpressapioptions)\> | Client configuration and request options. |

### Returns

[`ProtectMiddleware`](/sdks/express-backend/api-reference/handler-types/protectmiddleware)
