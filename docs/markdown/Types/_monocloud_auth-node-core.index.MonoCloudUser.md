---
rootSdk: Node.js Core
title: "MonoCloudUser"
category: Types
description: "Represents the authenticated user stored in a MonoCloud session."
---

# Type: MonoCloudUser

Represents the authenticated user stored in a MonoCloud session.

## Extends

- [`UserinfoResponse`](/sdks/nodejs-core/api-reference/types/userinforesponse)

## Indexable

> \[`key`: `string`\]: `unknown`

Additional provider-specific claims.

## Properties

| Property                                                    | Type                                                    | Description                                                                                        |
| ----------------------------------------------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `address?`                             | [`Address`](/sdks/nodejs-core/api-reference/types/address) | Postal address.                                                                                    |
| `amr?`                                     | `string`[]                                              | Authentication Methods References (AMR). Indicates how the user authenticated.                     |
| `birthdate?`                         | `string`                                                | Birthday.                                                                                          |
| `email?`                                 | `string`                                                | Email address.                                                                                     |
| `email_verified?`               | `boolean`                                               | Whether the email address has been verified by the provider.                                       |
| `family_name?`                     | `string`                                                | Surname(s) / last name.                                                                            |
| `gender?`                               | `string`                                                | Gender.                                                                                            |
| `given_name?`                       | `string`                                                | Given name(s) / first name.                                                                        |
| `groups?`                               | [`Group`](/sdks/nodejs-core/api-reference/types/group)[]   | Group memberships for the user.                                                                    |
| `idp?`                                     | `string`                                                | Identity Provider (IdP) identifier. Specifies the upstream provider used to authenticate the user. |
| `locale?`                               | `string`                                                | Locale.                                                                                            |
| `middle_name?`                     | `string`                                                | Middle name(s).                                                                                    |
| `name?`                                   | `string`                                                | Full name of the user (e.g. "Jane Doe").                                                           |
| `nickname?`                           | `string`                                                | Casual name used by the user.                                                                      |
| `phone_number?`                   | `string`                                                | Phone number (formatted in E.164 standard).                                                        |
| `phone_number_verified?` | `boolean`                                               | Whether the phone number has been verified by the provider.                                        |
| `picture?`                             | `string`                                                | URL of the user's profile picture.                                                                 |
| `preferred_username?`       | `string`                                                | Preferred username.                                                                                |
| `profile?`                             | `string`                                                | URL of the user's profile page.                                                                    |
| `sub`                                      | `string`                                                | Subject identifier - a unique, stable identifier for the user within the issuer.                   |
| `updated_at?`                       | `number`                                                | Time the user's information was last updated (seconds since epoch).                                |
| `website?`                             | `string`                                                | URL of the user's website.                                                                         |
| `zoneinfo?`                           | `string`                                                | Time zone name.                                                                                    |
