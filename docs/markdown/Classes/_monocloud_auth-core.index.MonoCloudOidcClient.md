---
rootSdk: Node.js
title: "MonoCloudOidcClient"
category: Classes
---

# Class: MonoCloudOidcClient

## Constructors

### Constructor

> **new MonoCloudOidcClient**(`tenantDomain`: `string`, `clientId`: `string`, `options?`: [`MonoCloudClientOptions`](/sdks/nodejs/api-reference/types/monocloudclientoptions)): `MonoCloudOidcClient`

#### Parameters

| Parameter      | Type                                                                                      |
| -------------- | ----------------------------------------------------------------------------------------- |
| `tenantDomain` | `string`                                                                                  |
| `clientId`     | `string`                                                                                  |
| `options?`     | [`MonoCloudClientOptions`](/sdks/nodejs/api-reference/types/monocloudclientoptions) |

#### Returns

`MonoCloudOidcClient`

## Methods

### authenticate()

> **authenticate**(`code`: `string`, `redirectUri`: `string`, `requestedScopes`: `string`, `resource?`: `string`, `options?`: [`AuthenticateOptions`](/sdks/nodejs/api-reference/types/authenticateoptions)): `Promise`\<[`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession)\>

Generates a session with user and tokens by exchanging authorization code from callback params.

#### Parameters

| Parameter         | Type                                                                                | Description                                                                                                                                                                                                         |
| ----------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `code`            | `string`                                                                            | The authorization code received from the callback.                                                                                                                                                                  |
| `redirectUri`     | `string`                                                                            | The redirect URI that was used in the authorization request.                                                                                                                                                        |
| `requestedScopes` | `string`                                                                            | A space-separated list of scopes originally requested via the `/authorize` endpoint. This is stored in the session to ensure the correct access token can be identified and refreshed during `refreshSession()`.    |
| `resource?`       | `string`                                                                            | A space-separated list of resource indicators originally requested via the `/authorize` endpoint. Used alongside scopes to uniquely identify and refresh the specific access token associated with these resources. |
| `options?`        | [`AuthenticateOptions`](/sdks/nodejs/api-reference/types/authenticateoptions) | Options for authenticating a user with authorization code.                                                                                                                                                          |

#### Returns

`Promise`\<[`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession)\>

The user's session containing authentication tokens and user information.

#### Throws

[MonoCloudValidationError](/sdks/nodejs/api-reference/error-classes/monocloudvalidationerror) - When the token scope does not contain the openid scope,
or if 'expires_in' or 'scope' is missing from the token response.

#### Throws

[MonoCloudOPError](/sdks/nodejs/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized.
OAuth 2.0 error response.

#### Throws

[MonoCloudTokenError](/sdks/nodejs/api-reference/error-classes/monocloudtokenerror) - If ID Token validation fails.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### authorizationUrl()

> **authorizationUrl**(`params`: [`AuthorizationParams`](/sdks/nodejs/api-reference/types/authorizationparams)): `Promise`\<`string`\>

Generates an authorization URL with specified parameters.

If no values are provided for `responseType`, or `codeChallengeMethod`, they default to `code`, and `S256`, respectively.

#### Parameters

| Parameter | Type                                                                                | Description                   |
| --------- | ----------------------------------------------------------------------------------- | ----------------------------- |
| `params`  | [`AuthorizationParams`](/sdks/nodejs/api-reference/types/authorizationparams) | Authorization URL parameters. |

#### Returns

`Promise`\<`string`\>

Tenant's authorization URL.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### decodeJwt()

> `static` **decodeJwt**(`jwt`: `string`): [`IdTokenClaims`](/sdks/nodejs/api-reference/types/idtokenclaims)

Decodes the payload of a JSON Web Token (JWT) and returns it as an object.

> Note: THIS METHOD DOES NOT VERIFY JWT TOKENS.

#### Parameters

| Parameter | Type     | Description    |
| --------- | -------- | -------------- |
| `jwt`     | `string` | JWT to decode. |

#### Returns

[`IdTokenClaims`](/sdks/nodejs/api-reference/types/idtokenclaims)

Decoded payload.

#### Throws

[MonoCloudTokenError](/sdks/nodejs/api-reference/error-classes/monocloudtokenerror) - If decoding fails

---

### endSessionUrl()

> **endSessionUrl**(`params`: [`EndSessionParameters`](/sdks/nodejs/api-reference/types/endsessionparameters)): `Promise`\<`string`\>

Generates OpenID end session URL for signing out.

Note - The `state` is added only when `postLogoutRedirectUri` is present.

#### Parameters

| Parameter | Type                                                                                  | Description                          |
| --------- | ------------------------------------------------------------------------------------- | ------------------------------------ |
| `params`  | [`EndSessionParameters`](/sdks/nodejs/api-reference/types/endsessionparameters) | Parameters to build end session URL. |

#### Returns

`Promise`\<`string`\>

Tenant's end session URL.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### exchangeAuthorizationCode()

> **exchangeAuthorizationCode**(`code`: `string`, `redirectUri`: `string`, `codeVerifier?`: `string`, `resource?`: `string`): `Promise`\<[`Tokens`](/sdks/nodejs/api-reference/types/tokens)\>

Exchanges an authorization code for tokens.

#### Parameters

| Parameter       | Type     | Description                                                             |
| --------------- | -------- | ----------------------------------------------------------------------- |
| `code`          | `string` | The authorization code received from the authorization server.          |
| `redirectUri`   | `string` | The redirect URI used in the initial authorization request.             |
| `codeVerifier?` | `string` | Code verifier for PKCE.                                                 |
| `resource?`     | `string` | Space-separated list of resources the access token should be scoped to. |

#### Returns

`Promise`\<[`Tokens`](/sdks/nodejs/api-reference/types/tokens)\>

Tokens obtained by exchanging an authorization code at the token endpoint.

#### Throws

[MonoCloudOPError](/sdks/nodejs/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized
OAuth 2.0 error response.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### getJwks()

> **getJwks**(`forceRefresh`: `boolean`): `Promise`\<[`Jwks`](/sdks/nodejs/api-reference/types/jwks)\>

Fetches the JSON Web Keys used to sign the ID token.
The JWKS is cached for 1 minute.

#### Parameters

| Parameter      | Type      | Description                                                                  |
| -------------- | --------- | ---------------------------------------------------------------------------- |
| `forceRefresh` | `boolean` | If `true`, bypasses the cache and fetches fresh set of JWKS from the server. |

#### Returns

`Promise`\<[`Jwks`](/sdks/nodejs/api-reference/types/jwks)\>

The JSON Web Key Set containing the public keys for token verification.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### getMetadata()

> **getMetadata**(`forceRefresh`: `boolean`): `Promise`\<[`IssuerMetadata`](/sdks/nodejs/api-reference/types/issuermetadata)\>

Fetches the authorization server metadata from the .well-known endpoint.
The metadata is cached for 1 minute.

#### Parameters

| Parameter      | Type      | Description                                                               |
| -------------- | --------- | ------------------------------------------------------------------------- |
| `forceRefresh` | `boolean` | If `true`, bypasses the cache and fetches fresh metadata from the server. |

#### Returns

`Promise`\<[`IssuerMetadata`](/sdks/nodejs/api-reference/types/issuermetadata)\>

The issuer metadata for the tenant, retrieved from the OpenID Connect discovery endpoint.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### pushedAuthorizationRequest()

> **pushedAuthorizationRequest**(`params`: [`PushedAuthorizationParams`](/sdks/nodejs/api-reference/types/pushedauthorizationparams)): `Promise`\<[`ParResponse`](/sdks/nodejs/api-reference/types/parresponse)\>

Performs a pushed authorization request.

#### Parameters

| Parameter | Type                                                                                            | Description               |
| --------- | ----------------------------------------------------------------------------------------------- | ------------------------- |
| `params`  | [`PushedAuthorizationParams`](/sdks/nodejs/api-reference/types/pushedauthorizationparams) | Authorization Parameters. |

#### Returns

`Promise`\<[`ParResponse`](/sdks/nodejs/api-reference/types/parresponse)\>

Response from Pushed Authorization Request (PAR) endpoint.

#### Throws

[MonoCloudOPError](/sdks/nodejs/api-reference/error-classes/monocloudoperror) - When the request is invalid.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### refetchUserInfo()

> **refetchUserInfo**(`accessToken`: [`AccessToken`](/sdks/nodejs/api-reference/types/accesstoken), `session`: [`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession), `options?`: [`RefetchUserInfoOptions`](/sdks/nodejs/api-reference/types/refetchuserinfooptions)): `Promise`\<[`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession)\>

Refetches user information for an existing session using the userinfo endpoint.
Updates the session's user object with the latest user information.

#### Parameters

| Parameter     | Type                                                                                      | Description                              |
| ------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------- |
| `accessToken` | [`AccessToken`](/sdks/nodejs/api-reference/types/accesstoken)                       | Access token used to fetch the userinfo. |
| `session`     | [`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession)             | The current MonoCloudSession.            |
| `options?`    | [`RefetchUserInfoOptions`](/sdks/nodejs/api-reference/types/refetchuserinfooptions) | Userinfo refetch options.                |

#### Returns

`Promise`\<[`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession)\>

Updated session with the latest userinfo.

#### Throws

[MonoCloudValidationError](/sdks/nodejs/api-reference/error-classes/monocloudvalidationerror) - When the token scope does not contain openid scope

#### Throws

[MonoCloudOPError](/sdks/nodejs/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized
OAuth 2.0 error response.

#### Throws

[MonoCloudTokenError](/sdks/nodejs/api-reference/error-classes/monocloudtokenerror) - If ID Token validation fails

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### refreshGrant()

> **refreshGrant**(`refreshToken`: `string`, `options?`: [`RefreshGrantOptions`](/sdks/nodejs/api-reference/types/refreshgrantoptions)): `Promise`\<[`Tokens`](/sdks/nodejs/api-reference/types/tokens)\>

Exchanges a refresh token for new tokens.

#### Parameters

| Parameter      | Type                                                                                | Description                                   |
| -------------- | ----------------------------------------------------------------------------------- | --------------------------------------------- |
| `refreshToken` | `string`                                                                            | The refresh token used to request new tokens. |
| `options?`     | [`RefreshGrantOptions`](/sdks/nodejs/api-reference/types/refreshgrantoptions) | Refresh grant options.                        |

#### Returns

`Promise`\<[`Tokens`](/sdks/nodejs/api-reference/types/tokens)\>

Tokens obtained by exchanging a refresh token at the token endpoint.

#### Throws

[MonoCloudOPError](/sdks/nodejs/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized
OAuth 2.0 error response.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### refreshSession()

> **refreshSession**(`session`: [`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession), `options?`: [`RefreshSessionOptions`](/sdks/nodejs/api-reference/types/refreshsessionoptions)): `Promise`\<[`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession)\>

Refreshes an existing session using the refresh token.
This function requests new tokens using the refresh token and optionally updates user information.

#### Parameters

| Parameter  | Type                                                                                    | Description                                                |
| ---------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `session`  | [`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession)           | The current MonoCloudSession containing the refresh token. |
| `options?` | [`RefreshSessionOptions`](/sdks/nodejs/api-reference/types/refreshsessionoptions) | Session refresh options.                                   |

#### Returns

`Promise`\<[`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession)\>

User's session containing refreshed authentication tokens and user information.

#### Throws

[MonoCloudValidationError](/sdks/nodejs/api-reference/error-classes/monocloudvalidationerror) - If the refresh token is not present in the session,
or if 'expires_in' or 'scope' (including the openid scope) is missing from the token response.

#### Throws

[MonoCloudOPError](/sdks/nodejs/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized
OAuth 2.0 error response.

#### Throws

[MonoCloudTokenError](/sdks/nodejs/api-reference/error-classes/monocloudtokenerror) - If ID Token validation fails

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### revokeToken()

> **revokeToken**(`token`: `string`, `tokenType?`: `string`): `Promise`\<`void`\>

Revokes an access token or refresh token, rendering it invalid for future use.

#### Parameters

| Parameter    | Type     | Description                                                    |
| ------------ | -------- | -------------------------------------------------------------- |
| `token`      | `string` | The token string to be revoked.                                |
| `tokenType?` | `string` | Hint about the token type ('access_token' or 'refresh_token'). |

#### Returns

`Promise`\<`void`\>

If token revocation succeeded.

#### Throws

[MonoCloudValidationError](/sdks/nodejs/api-reference/error-classes/monocloudvalidationerror) - If token is invalid or unsupported token type

#### Throws

[MonoCloudOPError](/sdks/nodejs/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized
OAuth 2.0 error response.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### userinfo()

> **userinfo**(`accessToken`: `string`): `Promise`\<[`UserinfoResponse`](/sdks/nodejs/api-reference/types/userinforesponse)\<[`Address`](/sdks/nodejs/api-reference/types/address)\>\>

Fetches userinfo associated with the provided access token.

#### Parameters

| Parameter     | Type     | Description                                     |
| ------------- | -------- | ----------------------------------------------- |
| `accessToken` | `string` | A valid access token used to retrieve userinfo. |

#### Returns

`Promise`\<[`UserinfoResponse`](/sdks/nodejs/api-reference/types/userinforesponse)\<[`Address`](/sdks/nodejs/api-reference/types/address)\>\>

The authenticated user's claims.

#### Throws

[MonoCloudOPError](/sdks/nodejs/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized
OAuth 2.0 error (e.g., 'invalid_token') in the 'WWW-Authenticate' header
following a 401 Unauthorized response.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

#### Throws

[MonoCloudValidationError](/sdks/nodejs/api-reference/error-classes/monocloudvalidationerror) - When the access token is invalid.

---

### validateIdToken()

> **validateIdToken**(`idToken`: `string`, `jwks`: [`Jwk`](/sdks/nodejs/api-reference/types/jwk)[], `clockSkew`: `number`, `clockTolerance`: `number`, `maxAge?`: `number`, `nonce?`: `string`): `Promise`\<[`IdTokenClaims`](/sdks/nodejs/api-reference/types/idtokenclaims)\>

Validates an ID Token.

#### Parameters

| Parameter        | Type                                                  | Description                                                                    |
| ---------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------ |
| `idToken`        | `string`                                              | The ID Token JWT string to validate.                                           |
| `jwks`           | [`Jwk`](/sdks/nodejs/api-reference/types/jwk)[] | Array of JSON Web Keys (JWK) used to verify the token's signature.             |
| `clockSkew`      | `number`                                              | Number of seconds to adjust the current time to account for clock differences. |
| `clockTolerance` | `number`                                              | Additional time tolerance in seconds for time-based claim validation.          |
| `maxAge?`        | `number`                                              | Maximum authentication age in seconds.                                         |
| `nonce?`         | `string`                                              | Nonce value to validate against the token's nonce claim.                       |

#### Returns

`Promise`\<[`IdTokenClaims`](/sdks/nodejs/api-reference/types/idtokenclaims)\>

Validated ID Token claims.

#### Throws

[MonoCloudTokenError](/sdks/nodejs/api-reference/error-classes/monocloudtokenerror) - If ID Token validation fails
