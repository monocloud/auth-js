---
rootSdk: Next.js
title: "MonoCloudOptions"
category: Types
---

# Type: MonoCloudOptions

Configuration options used to initialize the SDK client.

## Configuration Sources

Configuration values can be provided using either:

- **Constructor options** - passed when creating the client instance.
- **Environment variables** - using `MONOCLOUD_AUTH_*` variables.

When both are provided, **constructor options override environment variables**.

## Environment Variables

### Core Configuration (Required)

| Environment Variable           | Description                                                                                |
| ------------------------------ | ------------------------------------------------------------------------------------------ |
| `MONOCLOUD_AUTH_CLIENT_ID`     | Unique identifier for your application/client.                                             |
| `MONOCLOUD_AUTH_CLIENT_SECRET` | Application/client secret used for authentication.                                         |
| `MONOCLOUD_AUTH_TENANT_DOMAIN` | The domain of your MonoCloud tenant (for example, `https://your-tenant.us.monocloud.com`). |
| `MONOCLOUD_AUTH_APP_URL`       | The base URL where your application is hosted.                                             |
| `MONOCLOUD_AUTH_COOKIE_SECRET` | A long, random string used to encrypt and sign session cookies.                            |

### Authentication & Security

| Environment Variable                         | Description                                                                                                           |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `MONOCLOUD_AUTH_SCOPES`                      | Space-separated list of OIDC scopes to request (for example, `openid profile email`).                                 |
| `MONOCLOUD_AUTH_RESOURCE`                    | Default resource (audience) identifier used when issuing access tokens.                                               |
| `MONOCLOUD_AUTH_USE_PAR`                     | Enables Pushed Authorization Requests (PAR) for authorization flows.                                                  |
| `MONOCLOUD_AUTH_CLOCK_SKEW`                  | Allowed clock drift (in seconds) when validating token timestamps.                                                    |
| `MONOCLOUD_AUTH_FEDERATED_SIGNOUT`           | If `true`, signing out of the application also signs the user out of MonoCloud (SSO sign-out).                        |
| `MONOCLOUD_AUTH_RESPONSE_TIMEOUT`            | Maximum time (in milliseconds) to wait for responses from the authentication service.                                 |
| `MONOCLOUD_AUTH_ALLOW_QUERY_PARAM_OVERRIDES` | Allows authorization parameters (such as `scope`, `resource`, or `prompt`) to be overridden via URL query parameters. |
| `MONOCLOUD_AUTH_POST_LOGOUT_REDIRECT_URI`    | URL users are redirected to after a successful logout.                                                                |
| `MONOCLOUD_AUTH_FETCH_USER_INFO`             | Determines whether user profile data is fetched from the `UserInfo` endpoint after authorization.                     |
| `MONOCLOUD_AUTH_REFETCH_USER_INFO`           | If `true`, user information is re-fetched on each userinfo request.                                                   |
| `MONOCLOUD_AUTH_ID_TOKEN_SIGNING_ALG`        | Expected signing algorithm for ID tokens (for example, `RS256`).                                                      |
| `MONOCLOUD_AUTH_FILTERED_ID_TOKEN_CLAIMS`    | Space-separated list of ID token claims excluded from the session object.                                             |

### Routes

| Environment Variable           | Description                                                                               |
| ------------------------------ | ----------------------------------------------------------------------------------------- |
| `MONOCLOUD_AUTH_CALLBACK_URL`  | Application path where the authorization server redirects the user after authentication.  |
| `MONOCLOUD_AUTH_SIGNIN_URL`    | Internal route used to initiate the sign-in flow.                                         |
| `MONOCLOUD_AUTH_SIGNOUT_URL`   | Internal route used to initiate the sign-out flow.                                        |
| `MONOCLOUD_AUTH_USER_INFO_URL` | Route that exposes the authenticated user’s profile retrieved from the UserInfo endpoint. |

### Session Cookie Settings

| Environment Variable                       | Description                                                                 |
| ------------------------------------------ | --------------------------------------------------------------------------- |
| `MONOCLOUD_AUTH_SESSION_COOKIE_NAME`       | Name of the cookie used to store the authenticated user session.            |
| `MONOCLOUD_AUTH_SESSION_COOKIE_PATH`       | Path scope for which the session cookie is valid.                           |
| `MONOCLOUD_AUTH_SESSION_COOKIE_DOMAIN`     | Domain scope for which the session cookie is valid.                         |
| `MONOCLOUD_AUTH_SESSION_COOKIE_HTTP_ONLY`  | Prevents client-side scripts from accessing the session cookie.             |
| `MONOCLOUD_AUTH_SESSION_COOKIE_SECURE`     | Ensures the session cookie is only sent over HTTPS connections.             |
| `MONOCLOUD_AUTH_SESSION_COOKIE_SAME_SITE`  | SameSite policy applied to the session cookie (`lax`, `strict`, or `none`). |
| `MONOCLOUD_AUTH_SESSION_COOKIE_PERSISTENT` | Determines whether the session cookie persists across browser restarts.     |
| `MONOCLOUD_AUTH_SESSION_SLIDING`           | Enables sliding session expiration instead of absolute expiration.          |
| `MONOCLOUD_AUTH_SESSION_DURATION`          | Session lifetime in seconds.                                                |
| `MONOCLOUD_AUTH_SESSION_MAX_DURATION`      | Maximum allowed lifetime of a sliding session in seconds.                   |

### State Cookie Settings

| Environment Variable                     | Description                                                                                   |
| ---------------------------------------- | --------------------------------------------------------------------------------------------- |
| `MONOCLOUD_AUTH_STATE_COOKIE_NAME`       | Name of the cookie used to store OpenID Connect state and nonce values during authentication. |
| `MONOCLOUD_AUTH_STATE_COOKIE_PATH`       | Path scope for which the state cookie is valid.                                               |
| `MONOCLOUD_AUTH_STATE_COOKIE_DOMAIN`     | Domain scope for which the state cookie is valid.                                             |
| `MONOCLOUD_AUTH_STATE_COOKIE_SECURE`     | Ensures the state cookie is only sent over HTTPS connections.                                 |
| `MONOCLOUD_AUTH_STATE_COOKIE_SAME_SITE`  | SameSite policy applied to the state cookie (`lax`, `strict`, or `none`).                     |
| `MONOCLOUD_AUTH_STATE_COOKIE_PERSISTENT` | Determines whether the state cookie persists beyond the current browser session.              |

### Caching

| Environment Variable                     | Description                                                                       |
| ---------------------------------------- | --------------------------------------------------------------------------------- |
| `MONOCLOUD_AUTH_JWKS_CACHE_DURATION`     | Duration (in seconds) to cache the JSON Web Key Set (JWKS) used to verify tokens. |
| `MONOCLOUD_AUTH_METADATA_CACHE_DURATION` | Duration (in seconds) to cache the OpenID Connect discovery metadata.             |

## Extends

- `Partial`\<`Omit`\<[`MonoCloudOptionsBase`](/sdks/nodejs-core/api-reference/types/monocloudoptionsbase), `"defaultAuthParams"` \| `"session"` \| `"routes"` \| `"state"`\>\>

## Properties

| Property                                                          | Type                                                                                                  | Description                                                                                                                                                                                                                                     |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `allowQueryParamOverrides?` | `boolean`                                                                                             | Allows authorization parameters to be overridden using query parameters. When disabled, parameters such as `scope`, `resource`, `prompt`, and `login_hint` present in the request URL are ignored and cannot modify the authentication request. |
| `appUrl?`                                     | `string`                                                                                              | Base URL where the application is hosted. Used to construct redirect URLs and validate requests.                                                                                                                                                |
| `clientId?`                                 | `string`                                                                                              | Client identifier of the application registered in MonoCloud.                                                                                                                                                                                   |
| `clientSecret?`                         | `string`                                                                                              | Optional client secret used for confidential clients.                                                                                                                                                                                           |
| `clockSkew?`                               | `number`                                                                                              | Allowed clock skew (in seconds) when validating token timestamps.                                                                                                                                                                               |
| `cookieSecret?`                         | `string`                                                                                              | Secret used to encrypt and sign authentication cookies. This value should be long, random, and kept private.                                                                                                                                    |
| `debugger?`                                 | `string`                                                                                              | Identifier used for internal debugging/logging.                                                                                                                                                                                                 |
| `defaultAuthParams?`               | [`AuthorizationParams`](/sdks/nextjs/api-reference/types/authorizationparams)                          | Default authorization parameters automatically included in authentication requests unless explicitly overridden.                                                                                                                                |
| `federatedSignOut?`                 | `boolean`                                                                                             | When `true`, signing out also logs the user out of MonoCloud (Single Sign-Out).                                                                                                                                                                 |
| `fetchUserInfo?`                       | `boolean`                                                                                             | Fetch user profile data from the `UserInfo` endpoint after authentication completes.                                                                                                                                                            |
| `filteredIdTokenClaims?`       | `string`[]                                                                                            | List of ID token claims that should be removed before storing data in the session.                                                                                                                                                              |
| `idTokenSigningAlg?`               | [`SecurityAlgorithms`](/sdks/nextjs/api-reference/enums/securityalgorithms)         | Expected signing algorithm for ID tokens.                                                                                                                                                                                                       |
| `jwksCacheDuration?`               | `number`                                                                                              | Duration (in seconds) to cache the JWKS document.                                                                                                                                                                                               |
| `metadataCacheDuration?`       | `number`                                                                                              | Duration (in seconds) to cache OpenID discovery metadata.                                                                                                                                                                                       |
| `onBackChannelLogout?`           | [`OnBackChannelLogout`](/sdks/nextjs/api-reference/handler-types/onbackchannellogout)     | Invoked when a back-channel logout request is received.                                                                                                                                                                                         |
| `onSessionCreating?`               | [`OnSessionCreating`](/sdks/nextjs/api-reference/handler-types/onsessioncreating)         | Invoked before a session is created or updated. Can be used to modify session data or attach custom fields.                                                                                                                                     |
| `onSetApplicationState?`       | [`OnSetApplicationState`](/sdks/nextjs/api-reference/handler-types/onsetapplicationstate) | Invoked before authentication begins to attach custom application state.                                                                                                                                                                        |
| `postLogoutRedirectUri?`       | `string`                                                                                              | URL to redirect users to after logout completes.                                                                                                                                                                                                |
| `refetchUserInfo?`                   | `boolean`                                                                                             | Refetch user profile data whenever the application's `UserInfo` endpoint is invoked.                                                                                                                                                            |
| `resources?`                               | [`Indicator`](/sdks/nextjs/api-reference/types/indicator)[]                                            | Optional resource indicators available when requesting tokens via `getTokens()`.                                                                                                                                                                |
| `responseTimeout?`                   | `number`                                                                                              | Maximum time (in milliseconds) to wait for responses from the MonoCloud authorization server.                                                                                                                                                   |
| `routes?`                                     | `Partial`\<[`MonoCloudRoutes`](/sdks/nextjs/api-reference/types/monocloudroutes)\>                     | Overrides for built-in authentication route paths.                                                                                                                                                                                              |
| `session?`                                   | [`MonoCloudSessionOptions`](/sdks/nextjs/api-reference/types/monocloudsessionoptions)                  | Session configuration overrides.                                                                                                                                                                                                                |
| `state?`                                       | [`MonoCloudStatePartialOptions`](/sdks/nextjs/api-reference/types/monocloudstatepartialoptions)        | Configuration for authentication state handling.                                                                                                                                                                                                |
| `strictProfileSync?`               | `boolean`                                                                                             | Determines how user profile is updated when the session is updated. When enabled, the session user profile is fully replaced with a newly constructed profile derived from the latest ID token and, if applicable, the UserInfo response.       |
| `tenantDomain?`                         | `string`                                                                                              | MonoCloud tenant domain (for example, `https://your-tenant.us.monocloud.com`).                                                                                                                                                                  |
| `usePar?`                                     | `boolean`                                                                                             | Enables Pushed Authorization Requests (PAR). When enabled, authorization parameters are sent securely via the PAR endpoint instead of the browser.                                                                                              |
| `userAgent?`                               | `string`                                                                                              | Custom User-Agent value sent with requests to MonoCloud.                                                                                                                                                                                        |
