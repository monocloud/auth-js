---
rootSdk: Node.js
title: "DeviceAuthorizationResponse"
category: Types
description: "Response from the Device Authorization Request."
---

# Type: DeviceAuthorizationResponse

Response from the Device Authorization Request.

## Properties

| Property                                                            | Type     | Description                                                                                                       |
| ------------------------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| `device_code`                              | `string` | The device verification code.                                                                                     |
| `expires_in`                                | `number` | The lifetime in seconds of the "device_code" and "user_code".                                                     |
| `interval?`                                   | `number` | The minimum amount of time in seconds that the client SHOULD wait between polling requests to the token endpoint. |
| `user_code`                                  | `string` | The end-user verification code.                                                                                   |
| `verification_uri`                    | `string` | The end-user verification URI.                                                                                    |
| `verification_uri_complete?` | `string` | A verification URI that includes the "user_code" in the query parameter.                                          |
