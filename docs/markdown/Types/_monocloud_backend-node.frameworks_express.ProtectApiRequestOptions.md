---
rootSdk: Node.js Backend
title: "ProtectApiRequestOptions"
category: Types
framework: Express
description: "Options for customizing how access tokens and client certificates are extracted from incoming requests."
---

# Type: ProtectApiRequestOptions

Options for customizing how access tokens and client certificates are extracted from incoming requests.

## Type Parameters

| Type Parameter | Description         |
| -------------- | ------------------- |
| `T`            | Type of the request |

## certificateResolver
> `optional` **certificateResolver**: [`ClientCertificateResolver`](/sdks/express-backend/api-reference/handler-types/clientcertificateresolver)\<`T`\>

Custom callback to resolve the PEM-encoded client certificate from the request.

---

## tokenResolver
> `optional` **tokenResolver**: [`TokenResolver`](/sdks/express-backend/api-reference/handler-types/tokenresolver)\<`T`\>

Custom callback to extract the access token from the request.
When provided, overrides the default `Authorization: Bearer` header extraction.
