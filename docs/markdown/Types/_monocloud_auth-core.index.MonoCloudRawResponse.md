---
rootSdk: Node.js
title: "MonoCloudRawResponse"
category: Types
description: "The raw HTTP response an error was derived from. Only present on errors raised from an unsuccessful HTTP response."
---

# Type: MonoCloudRawResponse

The raw HTTP response an error was derived from. Only present on errors raised
from an unsuccessful HTTP response. The body and headers are captured verbatim
and may contain sensitive values, so avoid logging them as-is.

## Properties

| Property                             | Type                           | Description                       |
| ------------------------------------ | ------------------------------ | --------------------------------- |
| `body`             | `string`                       | Unparsed response body.           |
| `headers`       | `Record`\<`string`, `string`\> | Response headers.                 |
| `status`         | `number`                       | HTTP status code of the response. |
| `statusText` | `string`                       | HTTP status text of the response. |
