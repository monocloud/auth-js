---
rootSdk: Node.js
title: "IdTokenClaims"
category: Types
---

# Type: IdTokenClaims

Standard OpenID Connect ID Token claims.

## Extends

- [`UserinfoResponse`](/sdks/nodejs/api-reference/types/userinforesponse).[`JwtClaims`](/sdks/nodejs/api-reference/types/jwtclaims)

## Indexable

\[`key`: `string`\]: `unknown`

Additional provider-specific claims.

## Properties

| Property                                                    | Type                                               | Description                                                                                                   |
| ----------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `acr?`                                     | `string`                                           | Authentication Context Class Reference. Indicates the assurance level of the authentication performed.        |
| `address?`                             | [`Address`](/sdks/nodejs/api-reference/types/address) | Postal address.                                                                                               |
| `amr?`                                     | `string`[]                                         | Authentication Methods References. Lists the authentication methods used (for example: `pwd`, `mfa`, `otp`).  |
| `at_hash?`                             | `string`                                           | Access token hash. Used to validate access tokens returned alongside the ID token.                            |
| `aud`                                      | `string` \| `string`[]                             | Intended audience(s) of the token.                                                                            |
| `auth_time?`                         | `number`                                           | Time when the end-user authentication occurred (Unix epoch seconds).                                          |
| `azp?`                                     | `string`                                           | Authorized party - identifies the client to which the ID token was issued.                                    |
| `birthdate?`                         | `string`                                           | Birthday.                                                                                                     |
| `c_hash?`                               | `string`                                           | Authorization code hash. Used to validate authorization codes returned with hybrid flows.                     |
| `email?`                                 | `string`                                           | Email address.                                                                                                |
| `email_verified?`               | `boolean`                                          | Whether the email address has been verified by the provider.                                                  |
| `exp`                                      | `number`                                           | Expiration time of the token (Unix epoch seconds).                                                            |
| `family_name?`                     | `string`                                           | Surname(s) / last name.                                                                                       |
| `gender?`                               | `string`                                           | Gender.                                                                                                       |
| `given_name?`                       | `string`                                           | Given name(s) / first name.                                                                                   |
| `groups?`                               | [`Group`](/sdks/nodejs/api-reference/types/group)[]   | Group memberships for the user.                                                                               |
| `iat`                                      | `number`                                           | Time at which the token was issued (Unix epoch seconds).                                                      |
| `iss`                                      | `string`                                           | Issuer identifier - the authorization server that issued the token.                                           |
| `jti?`                                     | `string`                                           | JWT ID (unique identifier for the token).                                                                     |
| `locale?`                               | `string`                                           | Locale.                                                                                                       |
| `middle_name?`                     | `string`                                           | Middle name(s).                                                                                               |
| `name?`                                   | `string`                                           | Full name of the user (e.g. "Jane Doe").                                                                      |
| `nbf?`                                     | `number`                                           | Not-before time (Unix epoch seconds).                                                                         |
| `nickname?`                           | `string`                                           | Casual name used by the user.                                                                                 |
| `nonce?`                                 | `string`                                           | Nonce value used to associate the authentication request with the issued ID token and prevent replay attacks. |
| `phone_number?`                   | `string`                                           | Phone number (formatted in E.164 standard).                                                                   |
| `phone_number_verified?` | `boolean`                                          | Whether the phone number has been verified by the provider.                                                   |
| `picture?`                             | `string`                                           | URL of the user's profile picture.                                                                            |
| `preferred_username?`       | `string`                                           | Preferred username.                                                                                           |
| `profile?`                             | `string`                                           | URL of the user's profile page.                                                                               |
| `s_hash?`                               | `string`                                           | State hash (used in some hybrid flow validations).                                                            |
| `sub`                                      | `string`                                           | Subject identifier - a unique, stable identifier for the user within the issuer.                              |
| `updated_at?`                       | `number`                                           | Time the user's information was last updated (seconds since epoch).                                           |
| `website?`                             | `string`                                           | URL of the user's website.                                                                                    |
| `zoneinfo?`                           | `string`                                           | Time zone name.                                                                                               |
