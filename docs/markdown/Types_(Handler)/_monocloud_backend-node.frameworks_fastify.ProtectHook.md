---
rootSdk: Node.js Backend
title: "ProtectHook"
category: Handler Types
framework: Fastify
---

# Handler Type: ProtectHook

> **ProtectHook** = (`options?`: [`ProtectOptions`](/sdks/fastify-backend/api-reference/types/protectoptions)) => (`request`: `FastifyRequest`, `reply`: `FastifyReply`) => `Promise`\<`void`\>

Factory function that returns a Fastify `onRequest` hook for protecting API routes.

## Parameters

| Parameter  | Type                                                                         |
| ---------- | ---------------------------------------------------------------------------- |
| `options?` | [`ProtectOptions`](/sdks/fastify-backend/api-reference/types/protectoptions) |

## Returns

> (`request`: `FastifyRequest`, `reply`: `FastifyReply`): `Promise`\<`void`\>

### Parameters

| Parameter | Type             |
| --------- | ---------------- |
| `request` | `FastifyRequest` |
| `reply`   | `FastifyReply`   |

### Returns

`Promise`\<`void`\>
