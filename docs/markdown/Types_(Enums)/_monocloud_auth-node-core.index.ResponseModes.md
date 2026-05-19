---
rootSdk: Node.js Core
title: "ResponseModes"
category: Enums
description: "Supported OAuth 2.0 / OpenID Connect response_mode values."
---

# Enum: ResponseModes

> **ResponseModes** = `"form_post"` \| `"query"` \| `"fragment"`

Supported OAuth 2.0 / OpenID Connect `response_mode` values.

The response mode determines how authorization results are returned from the authorization endpoint to the client application.

## Type Declaration

- `form_post` - Returns authorization results using an HTTP POST request with parameters encoded in the request body.
- `query` - Returns authorization results as URL query parameters.
- `fragment` - Returns authorization results in the URL fragment.
