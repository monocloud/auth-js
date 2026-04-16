---
rootSdk: Node.js Backend
title: "protectApi"
category: Functions
framework: Fastify
---

# Function: protectApi

## Call Signature

> **protectApi**(`client`: [`MonoCloudBackendNodeClient`](/sdks/fastify-backend/api-reference/classes/monocloudbackendnodeclient), `requestOptions?`: [`ProtectApiRequestOptions`](/sdks/fastify-backend/api-reference/types/protectapirequestoptions)\<`FastifyRequest`\<`RouteGenericInterface`, `RawServerDefault`, `IncomingMessage`, `FastifySchema`, `FastifyTypeProviderDefault`, `unknown`, `FastifyBaseLogger`, `ResolveFastifyRequestType`\<`FastifyTypeProviderDefault`, `FastifySchema`, `RouteGenericInterface`\>\>\>): [`ProtectHook`](/sdks/fastify-backend/api-reference/handler-types/protecthook)

Creates a Fastify `onRequest` hook factory for protecting API routes using a pre-configured client.

### Parameters

| Parameter         | Type                                                                                                                                                                                                                                                                                                                                                                         | Description                                                                                                                     |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `client`          | [`MonoCloudBackendNodeClient`](/sdks/fastify-backend/api-reference/classes/monocloudbackendnodeclient)                                                                                                                                                                                                                                                                       | A pre-configured [MonoCloudBackendNodeClient](/sdks/fastify-backend/api-reference/classes/monocloudbackendnodeclient) instance. |
| `requestOptions?` | [`ProtectApiRequestOptions`](/sdks/fastify-backend/api-reference/types/protectapirequestoptions)\<`FastifyRequest`\<`RouteGenericInterface`, `RawServerDefault`, `IncomingMessage`, `FastifySchema`, `FastifyTypeProviderDefault`, `unknown`, `FastifyBaseLogger`, `ResolveFastifyRequestType`\<`FastifyTypeProviderDefault`, `FastifySchema`, `RouteGenericInterface`\>\>\> | Options for extracting tokens and certificates from the request.                                                                |

### Returns

[`ProtectHook`](/sdks/fastify-backend/api-reference/handler-types/protecthook)

## Call Signature

> **protectApi**(`options?`: `Partial`\<[`ProtectFastifyApiOptions`](/sdks/fastify-backend/api-reference/types/protectfastifyapioptions)\>): [`ProtectHook`](/sdks/fastify-backend/api-reference/handler-types/protecthook)

Creates a Fastify `onRequest` hook factory for protecting API routes.

A new [MonoCloudBackendNodeClient](/sdks/fastify-backend/api-reference/classes/monocloudbackendnodeclient) is created from the provided options,
or from environment variables if no options are specified.

### Parameters

| Parameter  | Type                                                                                                                       | Description                               |
| ---------- | -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| `options?` | `Partial`\<[`ProtectFastifyApiOptions`](/sdks/fastify-backend/api-reference/types/protectfastifyapioptions)\> | Client configuration and request options. |

### Returns

[`ProtectHook`](/sdks/fastify-backend/api-reference/handler-types/protecthook)
