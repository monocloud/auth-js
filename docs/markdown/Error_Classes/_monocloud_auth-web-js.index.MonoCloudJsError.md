---
rootSdk: JavaScript
title: "MonoCloudJsError"
category: Error Classes
description: "Error thrown when a general JavaScript or internal SDK failure occurs."
---

# Error Class: MonoCloudJsError

Error thrown when a general JavaScript or internal SDK failure occurs.

This error indicates an unexpected issue within the browser that does not fall under network, validation, or OAuth-specific categories.

## Extends

- [`MonoCloudAuthBaseError`](/sdks/web-js/api-reference/error-classes/monocloudauthbaseerror)

## Properties

| Property                | Type                                                                                  | Description                                        |
| ----------------------- | ------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `raw?` | [`MonoCloudRawResponse`](/sdks/nodejs/api-reference/types/monocloudrawresponse) | The raw HTTP response this error was derived from. |
