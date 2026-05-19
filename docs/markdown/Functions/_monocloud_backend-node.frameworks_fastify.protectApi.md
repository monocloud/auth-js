---
rootSdk: Node.js Backend
title: "protectApi"
category: Functions
framework: Fastify
description: "Creates a Fastify onRequest hook factory for protecting API routes using a pre-configured client."
---

# Function: protectApi

## Call Signature

> **protectApi**(`client`: [`MonoCloudBackendNodeClient`](/sdks/fastify-backend/api-reference/classes/monocloudbackendnodeclient), `options?`: [`ProtectApiRequestOptions`](/sdks/fastify-backend/api-reference/types/protectapirequestoptions)\<`FastifyRequest`\<`RouteGenericInterface`, `RawServerDefault`, `IncomingMessage`, `FastifySchema`, `FastifyTypeProviderDefault`, `unknown`, `FastifyBaseLogger`, `ResolveFastifyRequestType`\<`FastifyTypeProviderDefault`, `FastifySchema`, `RouteGenericInterface`\>\>\>): [`ProtectHook`](/sdks/fastify-backend/api-reference/handler-types/protecthook)

Creates a Fastify `onRequest` hook factory for protecting API routes using a pre-configured client.

### Parameters

| Parameter  | Type                                                                                                                                                                                                                                                                                                                                                                         | Description                                                                                                                     |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `client`   | [`MonoCloudBackendNodeClient`](/sdks/fastify-backend/api-reference/classes/monocloudbackendnodeclient)                                                                                                                                                                                                                                                                       | A pre-configured [MonoCloudBackendNodeClient](/sdks/fastify-backend/api-reference/classes/monocloudbackendnodeclient) instance. |
| `options?` | [`ProtectApiRequestOptions`](/sdks/fastify-backend/api-reference/types/protectapirequestoptions)\<`FastifyRequest`\<`RouteGenericInterface`, `RawServerDefault`, `IncomingMessage`, `FastifySchema`, `FastifyTypeProviderDefault`, `unknown`, `FastifyBaseLogger`, `ResolveFastifyRequestType`\<`FastifyTypeProviderDefault`, `FastifySchema`, `RouteGenericInterface`\>\>\> | Options for extracting tokens and certificates from the request.                                                                |

### Returns

[`ProtectHook`](/sdks/fastify-backend/api-reference/handler-types/protecthook)

## Call Signature

> **protectApi**(`options?`: [`ProtectApiRequestOptions`](/sdks/fastify-backend/api-reference/types/protectapirequestoptions)\<`FastifyRequest`\<`RouteGenericInterface`, `RawServerDefault`, `IncomingMessage`, `FastifySchema`, `FastifyTypeProviderDefault`, `unknown`, `FastifyBaseLogger`, `ResolveFastifyRequestType`\<`FastifyTypeProviderDefault`, `FastifySchema`, `RouteGenericInterface`\>\>\>): [`ProtectHook`](/sdks/fastify-backend/api-reference/handler-types/protecthook)

Creates a Fastify `onRequest` hook factory for protecting API routes.

A new [MonoCloudBackendNodeClient](/sdks/fastify-backend/api-reference/classes/monocloudbackendnodeclient) is created from the provided options,
or from environment variables.

### Parameters

| Parameter  | Type                                                                                                                                                                                                                                                                                                                                                                         | Description                                                      |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `options?` | [`ProtectApiRequestOptions`](/sdks/fastify-backend/api-reference/types/protectapirequestoptions)\<`FastifyRequest`\<`RouteGenericInterface`, `RawServerDefault`, `IncomingMessage`, `FastifySchema`, `FastifyTypeProviderDefault`, `unknown`, `FastifyBaseLogger`, `ResolveFastifyRequestType`\<`FastifyTypeProviderDefault`, `FastifySchema`, `RouteGenericInterface`\>\>\> | Options for extracting tokens and certificates from the request. |

### Returns

[`ProtectHook`](/sdks/fastify-backend/api-reference/handler-types/protecthook)
