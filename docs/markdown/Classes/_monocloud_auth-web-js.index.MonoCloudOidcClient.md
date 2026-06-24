---
rootSdk: JavaScript
title: "MonoCloudOidcClient"
category: Classes
description: "MonoCloudOidcClient is a class in the MonoCloud JavaScript SDK."
---

# Class: MonoCloudOidcClient

## Extends

- [`MonoCloudOidcClientBase`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase)

## Constructors

### Constructor

> **new MonoCloudOidcClient**(`tenantDomain`: `string`, `clientId`: `string`, `options?`: [`MonoCloudOidcClientOptions`](/sdks/nodejs/api-reference/types/monocloudoidcclientoptions)): `MonoCloudOidcClient`

Creates a new instance of MonoCloudOidcClient.

#### Parameters

| Parameter      | Type                                                                                              | Description                                           |
| -------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `tenantDomain` | `string`                                                                                          | The tenant domain URL.                                |
| `clientId`     | `string`                                                                                          | Client id of the application registered in MonoCloud. |
| `options?`     | [`MonoCloudOidcClientOptions`](/sdks/nodejs/api-reference/types/monocloudoidcclientoptions) | Additional client configuration options.              |

#### Returns

`MonoCloudOidcClient`

#### Overrides

[`MonoCloudOidcClientBase`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase).[`constructor`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase#constructor)

## Properties

| Property                                                   | Type                                                                                 | Description                                                                                                  |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| `fetcher?`                            | (`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`) => `Promise`\<`Response`\> | Custom fetch implementation used for making HTTP requests. Falls back to the global `fetch` if not provided. |
| `jwks?`                                  | [`Jwks`](/sdks/web-js/api-reference/types/jwks)                              | Cached JSON Web Key Set retrieved from the issuer's JWKS endpoint.                                           |
| `jwksCacheDuration`         | `number`                                                                             | Duration (in seconds) for which the JWKS is cached. Defaults to 300 (5 minutes).                             |
| `jwksCacheExpiry`             | `number`                                                                             | Timestamp (in seconds) when the cached JWKS expires.                                                         |
| `metadata?`                          | [`IssuerMetadata`](/sdks/web-js/api-reference/types/issuermetadata)          | Cached issuer metadata retrieved from the OpenID Connect discovery endpoint.                                 |
| `metadataCacheDuration` | `number`                                                                             | Duration (in seconds) for which the metadata is cached. Defaults to 300 (5 minutes).                         |
| `metadataCacheExpiry`     | `number`                                                                             | Timestamp (in seconds) when the cached metadata expires.                                                     |
| `tenantDomain`                   | `string`                                                                             | The normalized tenant domain URL used as the base for discovery endpoints.                                   |

## Methods

### authenticate()

> **authenticate**(`code`: `string`, `redirectUri`: `string`, `requestedScopes`: `string`, `resource?`: `string`, `options?`: [`AuthenticateOptions`](/sdks/web-js/api-reference/types/authenticateoptions)): `Promise`\<[`MonoCloudSession`](/sdks/web-js/api-reference/types/monocloudsession)\>

Generates a session with user and tokens by exchanging authorization code from callback params.

#### Parameters

| Parameter         | Type                                                                                  | Description                                                                                                                                                                                                         |
| ----------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `code`            | `string`                                                                              | The authorization code received from the callback.                                                                                                                                                                  |
| `redirectUri`     | `string`                                                                              | The redirect URI that was used in the authorization request.                                                                                                                                                        |
| `requestedScopes` | `string`                                                                              | A space-separated list of scopes originally requested via the `/authorize` endpoint. This is stored in the session to ensure the correct access token can be identified and refreshed during `refreshSession()`.    |
| `resource?`       | `string`                                                                              | A space-separated list of resource indicators originally requested via the `/authorize` endpoint. Used alongside scopes to uniquely identify and refresh the specific access token associated with these resources. |
| `options?`        | [`AuthenticateOptions`](/sdks/web-js/api-reference/types/authenticateoptions) | Options for authenticating a user with authorization code.                                                                                                                                                          |

#### Returns

`Promise`\<[`MonoCloudSession`](/sdks/web-js/api-reference/types/monocloudsession)\>

The user's session containing authentication tokens and user information.

#### Throws

[MonoCloudValidationError](/sdks/web-js/api-reference/error-classes/monocloudvalidationerror) - When the token scope does not contain the openid scope,
or if 'expires_in' or 'scope' is missing from the token response.

#### Throws

[MonoCloudOPError](/sdks/web-js/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized.
OAuth 2.0 error response.

#### Throws

[MonoCloudTokenError](/sdks/web-js/api-reference/error-classes/monocloudtokenerror) - If ID Token validation fails.

#### Throws

[MonoCloudHttpError](/sdks/web-js/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### authorizationUrl()

> **authorizationUrl**(`params`: [`AuthorizationParams`](/sdks/web-js/api-reference/types/authorizationparams)): `Promise`\<`string`\>

Generates an authorization URL with specified parameters.

If no values are provided for `responseType`, or `codeChallengeMethod`, they default to `code`, and `S256`, respectively.

#### Parameters

| Parameter | Type                                                                                  | Description                   |
| --------- | ------------------------------------------------------------------------------------- | ----------------------------- |
| `params`  | [`AuthorizationParams`](/sdks/web-js/api-reference/types/authorizationparams) | Authorization URL parameters. |

#### Returns

`Promise`\<`string`\>

Tenant's authorization URL.

#### Throws

[MonoCloudHttpError](/sdks/web-js/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### decodeJwt()

> `static` **decodeJwt**(`jwt`: `string`): [`JwtClaims`](/sdks/nodejs/api-reference/types/jwtclaims)

Decodes the payload of a JSON Web Token (JWT) and returns it as an object.

> Note: THIS METHOD DOES NOT VERIFY JWT TOKENS.

#### Parameters

| Parameter | Type     | Description    |
| --------- | -------- | -------------- |
| `jwt`     | `string` | JWT to decode. |

#### Returns

[`JwtClaims`](/sdks/nodejs/api-reference/types/jwtclaims)

Decoded payload.

#### Throws

[MonoCloudTokenError](/sdks/nodejs/api-reference/error-classes/monocloudtokenerror) - If decoding fails

#### Inherited from

[`MonoCloudOidcClientBase`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase).[`decodeJwt`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase#decodejwt)

---

### deviceAuthorizationGrant()

> **deviceAuthorizationGrant**(`deviceCode`: `string`): `Promise`\<[`Tokens`](/sdks/web-js/api-reference/types/tokens)\>

Exchanges a device code for tokens.

#### Parameters

| Parameter    | Type     | Description                                                    |
| ------------ | -------- | -------------------------------------------------------------- |
| `deviceCode` | `string` | The device code received from the device authorization server. |

#### Returns

`Promise`\<[`Tokens`](/sdks/web-js/api-reference/types/tokens)\>

Tokens obtained by exchanging a device code at the token endpoint.

#### Throws

[MonoCloudOPError](/sdks/web-js/api-reference/error-classes/monocloudoperror) - When the authorization server returns a standardized
OAuth 2.0 error response.

#### Throws

[MonoCloudHttpError](/sdks/web-js/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### deviceAuthorizationRequest()

> **deviceAuthorizationRequest**(`params`: [`DeviceAuthorizationParams`](/sdks/nodejs/api-reference/types/deviceauthorizationparams)): `Promise`\<[`DeviceAuthorizationResponse`](/sdks/nodejs/api-reference/types/deviceauthorizationresponse)\>

Performs a device authorization request.

#### Parameters

| Parameter | Type                                                                                            | Description                      |
| --------- | ----------------------------------------------------------------------------------------------- | -------------------------------- |
| `params`  | [`DeviceAuthorizationParams`](/sdks/nodejs/api-reference/types/deviceauthorizationparams) | Device Authorization Parameters. |

#### Returns

`Promise`\<[`DeviceAuthorizationResponse`](/sdks/nodejs/api-reference/types/deviceauthorizationresponse)\>

Response from Device Authorization endpoint.

#### Throws

[MonoCloudOPError](/sdks/web-js/api-reference/error-classes/monocloudoperror) - When the request is invalid.

#### Throws

[MonoCloudHttpError](/sdks/web-js/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### endSessionUrl()

> **endSessionUrl**(`params`: [`EndSessionParameters`](/sdks/web-js/api-reference/types/endsessionparameters)): `Promise`\<`string`\>

Generates OpenID end session URL for signing out.

Note - The `state` is added only when `postLogoutRedirectUri` is present.

#### Parameters

| Parameter | Type                                                                                    | Description                          |
| --------- | --------------------------------------------------------------------------------------- | ------------------------------------ |
| `params`  | [`EndSessionParameters`](/sdks/web-js/api-reference/types/endsessionparameters) | Parameters to build end session URL. |

#### Returns

`Promise`\<`string`\>

Tenant's end session URL.

#### Throws

[MonoCloudHttpError](/sdks/web-js/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### exchangeAuthorizationCode()

> **exchangeAuthorizationCode**(`code`: `string`, `redirectUri`: `string`, `codeVerifier?`: `string`, `resource?`: `string`): `Promise`\<[`Tokens`](/sdks/web-js/api-reference/types/tokens)\>

Exchanges an authorization code for tokens.

#### Parameters

| Parameter       | Type     | Description                                                             |
| --------------- | -------- | ----------------------------------------------------------------------- |
| `code`          | `string` | The authorization code received from the authorization server.          |
| `redirectUri`   | `string` | The redirect URI used in the initial authorization request.             |
| `codeVerifier?` | `string` | Code verifier for PKCE.                                                 |
| `resource?`     | `string` | Space-separated list of resources the access token should be scoped to. |

#### Returns

`Promise`\<[`Tokens`](/sdks/web-js/api-reference/types/tokens)\>

Tokens obtained by exchanging an authorization code at the token endpoint.

#### Throws

[MonoCloudOPError](/sdks/web-js/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized
OAuth 2.0 error response.

#### Throws

[MonoCloudHttpError](/sdks/web-js/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### getJwks()

> **getJwks**(`forceRefresh?`: `boolean`): `Promise`\<[`Jwks`](/sdks/web-js/api-reference/types/jwks)\>

Fetches the JSON Web Keys used to sign the ID token.
The JWKS is cached for 5 minutes by default.

#### Parameters

| Parameter      | Type      | Description                                                                  |
| -------------- | --------- | ---------------------------------------------------------------------------- |
| `forceRefresh` | `boolean` | If `true`, bypasses the cache and fetches fresh set of JWKS from the server. |

#### Returns

`Promise`\<[`Jwks`](/sdks/web-js/api-reference/types/jwks)\>

The JSON Web Key Set containing the public keys for token verification.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

#### Inherited from

[`MonoCloudOidcClientBase`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase).[`getJwks`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase#getjwks)

---

### getMetadata()

> **getMetadata**(`forceRefresh?`: `boolean`): `Promise`\<[`IssuerMetadata`](/sdks/web-js/api-reference/types/issuermetadata)\>

Fetches the authorization server metadata from the .well-known endpoint.
The metadata is cached for 5 minutes by default.

#### Parameters

| Parameter      | Type      | Description                                                               |
| -------------- | --------- | ------------------------------------------------------------------------- |
| `forceRefresh` | `boolean` | If `true`, bypasses the cache and fetches fresh metadata from the server. |

#### Returns

`Promise`\<[`IssuerMetadata`](/sdks/web-js/api-reference/types/issuermetadata)\>

The issuer metadata for the tenant, retrieved from the OpenID Connect discovery endpoint.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

#### Inherited from

[`MonoCloudOidcClientBase`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase).[`getMetadata`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase#getmetadata)

---

### pushedAuthorizationRequest()

> **pushedAuthorizationRequest**(`params`: [`PushedAuthorizationParams`](/sdks/web-js/api-reference/types/pushedauthorizationparams)): `Promise`\<[`ParResponse`](/sdks/web-js/api-reference/types/parresponse)\>

Performs a pushed authorization request.

#### Parameters

| Parameter | Type                                                                                              | Description               |
| --------- | ------------------------------------------------------------------------------------------------- | ------------------------- |
| `params`  | [`PushedAuthorizationParams`](/sdks/web-js/api-reference/types/pushedauthorizationparams) | Authorization Parameters. |

#### Returns

`Promise`\<[`ParResponse`](/sdks/web-js/api-reference/types/parresponse)\>

Response from Pushed Authorization Request (PAR) endpoint.

#### Throws

[MonoCloudOPError](/sdks/web-js/api-reference/error-classes/monocloudoperror) - When the request is invalid.

#### Throws

[MonoCloudHttpError](/sdks/web-js/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### refetchUserInfo()

> **refetchUserInfo**(`accessToken`: [`AccessToken`](/sdks/web-js/api-reference/types/accesstoken), `session`: [`MonoCloudSession`](/sdks/web-js/api-reference/types/monocloudsession), `options?`: [`RefetchUserInfoOptions`](/sdks/web-js/api-reference/types/refetchuserinfooptions)): `Promise`\<[`MonoCloudSession`](/sdks/web-js/api-reference/types/monocloudsession)\>

Refetches user information for an existing session using the userinfo endpoint.
Updates the session's user object with the latest user information.

#### Parameters

| Parameter     | Type                                                                                        | Description                              |
| ------------- | ------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `accessToken` | [`AccessToken`](/sdks/web-js/api-reference/types/accesstoken)                       | Access token used to fetch the userinfo. |
| `session`     | [`MonoCloudSession`](/sdks/web-js/api-reference/types/monocloudsession)             | The current MonoCloudSession.            |
| `options?`    | [`RefetchUserInfoOptions`](/sdks/web-js/api-reference/types/refetchuserinfooptions) | Userinfo refetch options.                |

#### Returns

`Promise`\<[`MonoCloudSession`](/sdks/web-js/api-reference/types/monocloudsession)\>

Updated session with the latest userinfo.

#### Throws

[MonoCloudValidationError](/sdks/web-js/api-reference/error-classes/monocloudvalidationerror) - When the token scope does not contain openid scope

#### Throws

[MonoCloudOPError](/sdks/web-js/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized
OAuth 2.0 error response.

#### Throws

[MonoCloudTokenError](/sdks/web-js/api-reference/error-classes/monocloudtokenerror) - If ID Token validation fails

#### Throws

[MonoCloudHttpError](/sdks/web-js/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### refreshGrant()

> **refreshGrant**(`refreshToken`: `string`, `options?`: [`RefreshGrantOptions`](/sdks/web-js/api-reference/types/refreshgrantoptions)): `Promise`\<[`Tokens`](/sdks/web-js/api-reference/types/tokens)\>

Exchanges a refresh token for new tokens.

#### Parameters

| Parameter      | Type                                                                                  | Description                                   |
| -------------- | ------------------------------------------------------------------------------------- | --------------------------------------------- |
| `refreshToken` | `string`                                                                              | The refresh token used to request new tokens. |
| `options?`     | [`RefreshGrantOptions`](/sdks/web-js/api-reference/types/refreshgrantoptions) | Refresh grant options.                        |

#### Returns

`Promise`\<[`Tokens`](/sdks/web-js/api-reference/types/tokens)\>

Tokens obtained by exchanging a refresh token at the token endpoint.

#### Throws

[MonoCloudOPError](/sdks/web-js/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized
OAuth 2.0 error response.

#### Throws

[MonoCloudHttpError](/sdks/web-js/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### refreshSession()

> **refreshSession**(`session`: [`MonoCloudSession`](/sdks/web-js/api-reference/types/monocloudsession), `options?`: [`RefreshSessionOptions`](/sdks/web-js/api-reference/types/refreshsessionoptions)): `Promise`\<[`MonoCloudSession`](/sdks/web-js/api-reference/types/monocloudsession)\>

Refreshes an existing session using the refresh token.
This function requests new tokens using the refresh token and optionally updates user information.

#### Parameters

| Parameter  | Type                                                                                      | Description                                                |
| ---------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `session`  | [`MonoCloudSession`](/sdks/web-js/api-reference/types/monocloudsession)           | The current MonoCloudSession containing the refresh token. |
| `options?` | [`RefreshSessionOptions`](/sdks/web-js/api-reference/types/refreshsessionoptions) | Session refresh options.                                   |

#### Returns

`Promise`\<[`MonoCloudSession`](/sdks/web-js/api-reference/types/monocloudsession)\>

User's session containing refreshed authentication tokens and user information.

#### Throws

[MonoCloudValidationError](/sdks/web-js/api-reference/error-classes/monocloudvalidationerror) - If the refresh token is not present in the session,
or if 'expires_in' or 'scope' (including the openid scope) is missing from the token response.

#### Throws

[MonoCloudOPError](/sdks/web-js/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized
OAuth 2.0 error response.

#### Throws

[MonoCloudTokenError](/sdks/web-js/api-reference/error-classes/monocloudtokenerror) - If ID Token validation fails

#### Throws

[MonoCloudHttpError](/sdks/web-js/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
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

[MonoCloudValidationError](/sdks/web-js/api-reference/error-classes/monocloudvalidationerror) - If token is invalid or unsupported token type

#### Throws

[MonoCloudOPError](/sdks/web-js/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized
OAuth 2.0 error response.

#### Throws

[MonoCloudHttpError](/sdks/web-js/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

### userinfo()

> **userinfo**(`accessToken`: `string`): `Promise`\<[`UserinfoResponse`](/sdks/web-js/api-reference/types/userinforesponse)\<[`Address`](/sdks/web-js/api-reference/types/address)\>\>

Fetches userinfo associated with the provided access token.

#### Parameters

| Parameter     | Type     | Description                                     |
| ------------- | -------- | ----------------------------------------------- |
| `accessToken` | `string` | A valid access token used to retrieve userinfo. |

#### Returns

`Promise`\<[`UserinfoResponse`](/sdks/web-js/api-reference/types/userinforesponse)\<[`Address`](/sdks/web-js/api-reference/types/address)\>\>

The authenticated user's claims.

#### Throws

[MonoCloudOPError](/sdks/web-js/api-reference/error-classes/monocloudoperror) - When the OpenID Provider returns a standardized
OAuth 2.0 error (e.g., 'invalid_token') in the 'WWW-Authenticate' header
following a 401 Unauthorized response.

#### Throws

[MonoCloudHttpError](/sdks/web-js/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

#### Throws

[MonoCloudValidationError](/sdks/web-js/api-reference/error-classes/monocloudvalidationerror) - When the access token is invalid.

---

### validateIdToken()

> **validateIdToken**(`idToken`: `string`, `jwks`: [`Jwk`](/sdks/web-js/api-reference/types/jwk)[], `clockSkew`: `number`, `clockTolerance`: `number`, `maxAge?`: `number`, `nonce?`: `string`): `Promise`\<[`IdTokenClaims`](/sdks/web-js/api-reference/types/idtokenclaims)\>

Validates an ID Token.

#### Parameters

| Parameter        | Type                                                    | Description                                                                    |
| ---------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `idToken`        | `string`                                                | The ID Token JWT string to validate.                                           |
| `jwks`           | [`Jwk`](/sdks/web-js/api-reference/types/jwk)[] | Array of JSON Web Keys (JWK) used to verify the token's signature.             |
| `clockSkew`      | `number`                                                | Number of seconds to adjust the current time to account for clock differences. |
| `clockTolerance` | `number`                                                | Additional time tolerance in seconds for time-based claim validation.          |
| `maxAge?`        | `number`                                                | Maximum authentication age in seconds.                                         |
| `nonce?`         | `string`                                                | Nonce value to validate against the token's nonce claim.                       |

#### Returns

`Promise`\<[`IdTokenClaims`](/sdks/web-js/api-reference/types/idtokenclaims)\>

Validated ID Token claims.

#### Throws

[MonoCloudTokenError](/sdks/web-js/api-reference/error-classes/monocloudtokenerror) - If ID Token validation fails
