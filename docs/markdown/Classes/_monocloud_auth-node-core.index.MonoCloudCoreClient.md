---
rootSdk: Node.js Core
title: "MonoCloudCoreClient"
category: Classes
---

# Class: MonoCloudCoreClient

## Constructors

### Constructor

> **new MonoCloudCoreClient**(`partialOptions?`: [`MonoCloudOptions`](/sdks/nodejs-core/api-reference/types/monocloudoptions)): `MonoCloudCoreClient`

#### Parameters

| Parameter         | Type                                                                               |
| ----------------- | ---------------------------------------------------------------------------------- |
| `partialOptions?` | [`MonoCloudOptions`](/sdks/nodejs-core/api-reference/types/monocloudoptions) |

#### Returns

`MonoCloudCoreClient`

## Properties

| Property                             | Type                                                                       |
| ------------------------------------ | -------------------------------------------------------------------------- |
| `oidcClient` | [`MonoCloudOidcClient`](/sdks/nodejs/api-reference/classes/monocloudoidcclient) |

## Methods

### backChannelLogout()

> **backChannelLogout**(`request`: [`MonoCloudRequest`](/sdks/nodejs-core/api-reference/types/monocloudrequest), `response`: [`MonoCloudResponse`](/sdks/nodejs-core/api-reference/types/monocloudresponse)): `Promise`\<`any`\>

Handles Back-Channel Logout notifications from the identity provider.

Validates the Logout Token and triggers the `onBackChannelLogout` callback defined in options.

#### Parameters

| Parameter  | Type                                                                                 | Description                |
| ---------- | ------------------------------------------------------------------------------------ | -------------------------- |
| `request`  | [`MonoCloudRequest`](/sdks/nodejs-core/api-reference/types/monocloudrequest)   | MonoCloud request object.  |
| `response` | [`MonoCloudResponse`](/sdks/nodejs-core/api-reference/types/monocloudresponse) | MonoCloud response object. |

#### Returns

`Promise`\<`any`\>

A promise that resolves when the logout notification has been processed.

#### Throws

[MonoCloudValidationError](/sdks/nodejs-core/api-reference/error-classes/monocloudvalidationerror) If the logout token is missing or invalid.

---

### callback()

> **callback**(`request`: [`MonoCloudRequest`](/sdks/nodejs-core/api-reference/types/monocloudrequest), `response`: [`MonoCloudResponse`](/sdks/nodejs-core/api-reference/types/monocloudresponse), `callbackOptions?`: [`CallbackOptions`](/sdks/nodejs-core/api-reference/types/callbackoptions)): `Promise`\<`any`\>

Handles the OpenID callback after the user authenticates with MonoCloud.

Processes the authorization code, validates the state and nonce, exchanges the code for tokens,
initializes the user session, and performs the final redirect to the application's return URL.

#### Parameters

| Parameter          | Type                                                                                 | Description                                      |
| ------------------ | ------------------------------------------------------------------------------------ | ------------------------------------------------ |
| `request`          | [`MonoCloudRequest`](/sdks/nodejs-core/api-reference/types/monocloudrequest)   | MonoCloud request object.                        |
| `response`         | [`MonoCloudResponse`](/sdks/nodejs-core/api-reference/types/monocloudresponse) | MonoCloud response object.                       |
| `callbackOptions?` | [`CallbackOptions`](/sdks/nodejs-core/api-reference/types/callbackoptions)     | Optional configuration for the callback handler. |

#### Returns

`Promise`\<`any`\>

A promise that resolves when the callback processing and redirection are complete.

#### Throws

[MonoCloudValidationError](/sdks/nodejs-core/api-reference/error-classes/monocloudvalidationerror) If the state is mismatched or tokens are invalid.

---

### destroySession()

> **destroySession**(`request`: [`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest), `response`: [`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse)): `Promise`\<`void`\>

Destroys the local user session.

#### Parameters

| Parameter  | Type                                                                                               | Description                       |
| ---------- | -------------------------------------------------------------------------------------------------- | --------------------------------- |
| `request`  | [`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest)   | MonoCloud cookie request object.  |
| `response` | [`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse) | MonoCloud cookie response object. |

#### Returns

`Promise`\<`void`\>

#### Remarks

This does not perform federated sign-out. For identity provider sign-out, use `signOut` handler.

---

### getOptions()

> **getOptions**(): [`MonoCloudOptionsBase`](/sdks/nodejs-core/api-reference/types/monocloudoptionsbase)

Returns a copy of the current client configuration options.

#### Returns

[`MonoCloudOptionsBase`](/sdks/nodejs-core/api-reference/types/monocloudoptionsbase)

A copy of the initialized configuration.

---

### getSession()

> **getSession**(`request`: [`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest), `response`: [`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse)): `Promise`\<[`MonoCloudSession`](/sdks/nodejs-core/api-reference/types/monocloudsession) \| `undefined`\>

Retrieves the current user's session data.

#### Parameters

| Parameter  | Type                                                                                               | Description                       |
| ---------- | -------------------------------------------------------------------------------------------------- | --------------------------------- |
| `request`  | [`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest)   | MonoCloud cookie request object.  |
| `response` | [`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse) | MonoCloud cookie response object. |

#### Returns

`Promise`\<[`MonoCloudSession`](/sdks/nodejs-core/api-reference/types/monocloudsession) \| `undefined`\>

Session or `undefined`.

---

### getTokens()

> **getTokens**(`request`: [`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest), `response`: [`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse), `options?`: [`GetTokensOptions`](/sdks/nodejs-core/api-reference/types/gettokensoptions)): `Promise`\<[`MonoCloudTokens`](/sdks/nodejs-core/api-reference/types/monocloudtokens)\>

Retrieves active tokens (Access, ID, Refresh), performing a refresh if they are expired or missing.

#### Parameters

| Parameter  | Type                                                                                               | Description                                                                   |
| ---------- | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `request`  | [`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest)   | MonoCloud cookie request object.                                              |
| `response` | [`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse) | MonoCloud cookie response object.                                             |
| `options?` | [`GetTokensOptions`](/sdks/nodejs-core/api-reference/types/gettokensoptions)                 | Configuration for token retrieval (force refresh, specific scopes/resources). |

#### Returns

`Promise`\<[`MonoCloudTokens`](/sdks/nodejs-core/api-reference/types/monocloudtokens)\>

Fetched tokens.

#### Throws

[MonoCloudValidationError](/sdks/nodejs-core/api-reference/error-classes/monocloudvalidationerror) If the session does not exist or tokens cannot be found/refreshed.

---

### isAuthenticated()

> **isAuthenticated**(`request`: [`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest), `response`: [`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse)): `Promise`\<`boolean`\>

Checks if the current request has an active and authenticated session.

#### Parameters

| Parameter  | Type                                                                                               | Description                       |
| ---------- | -------------------------------------------------------------------------------------------------- | --------------------------------- |
| `request`  | [`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest)   | MonoCloud cookie request object.  |
| `response` | [`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse) | MonoCloud cookie response object. |

#### Returns

`Promise`\<`boolean`\>

`true` if a valid session with user data exists, `false` otherwise.

---

### isUserInGroup()

> **isUserInGroup**(`request`: [`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest), `response`: [`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse), `groups`: `string`[], `groupsClaim?`: `string`, `matchAll?`: `boolean`): `Promise`\<`boolean`\>

Checks if the current session user belongs to the specified groups.

#### Parameters

| Parameter      | Type                                                                                               | Description                                                                          |
| -------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `request`      | [`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest)   | MonoCloud cookie request object.                                                     |
| `response`     | [`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse) | MonoCloud cookie response object.                                                    |
| `groups`       | `string`[]                                                                                         | List of group names or IDs to check.                                                 |
| `groupsClaim?` | `string`                                                                                           | Optional claim name that holds groups. Defaults to "groups".                         |
| `matchAll?`    | `boolean`                                                                                          | If `true`, requires membership in all groups; otherwise any one group is sufficient. |

#### Returns

`Promise`\<`boolean`\>

`true` if the user satisfies the group condition, `false` otherwise.

---

### signIn()

> **signIn**(`request`: [`MonoCloudRequest`](/sdks/nodejs-core/api-reference/types/monocloudrequest), `response`: [`MonoCloudResponse`](/sdks/nodejs-core/api-reference/types/monocloudresponse), `signInOptions?`: [`SignInOptions`](/sdks/nodejs-core/api-reference/types/signinoptions)): `Promise`\<`any`\>

Initiates the sign-in flow by redirecting the user to the MonoCloud authorization endpoint.

This method handles scope and resource merging, state generation (nonce, state, PKCE),
and constructing the final authorization URL.

#### Parameters

| Parameter        | Type                                                                                 | Description                                      |
| ---------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------ |
| `request`        | [`MonoCloudRequest`](/sdks/nodejs-core/api-reference/types/monocloudrequest)   | MonoCloud request object.                        |
| `response`       | [`MonoCloudResponse`](/sdks/nodejs-core/api-reference/types/monocloudresponse) | MonoCloud response object.                       |
| `signInOptions?` | [`SignInOptions`](/sdks/nodejs-core/api-reference/types/signinoptions)         | Configuration to customize the sign-in behavior. |

#### Returns

`Promise`\<`any`\>

A promise that resolves when the callback processing and redirection are complete.

#### Throws

[MonoCloudValidationError](/sdks/nodejs-core/api-reference/error-classes/monocloudvalidationerror) When validation of parameters or state fails.

---

### signOut()

> **signOut**(`request`: [`MonoCloudRequest`](/sdks/nodejs-core/api-reference/types/monocloudrequest), `response`: [`MonoCloudResponse`](/sdks/nodejs-core/api-reference/types/monocloudresponse), `signOutOptions?`: [`SignOutOptions`](/sdks/nodejs-core/api-reference/types/signoutoptions)): `Promise`\<`any`\>

Initiates the sign-out flow, destroying the local session and optionally performing federated sign-out.

#### Parameters

| Parameter         | Type                                                                                 | Description                                                    |
| ----------------- | ------------------------------------------------------------------------------------ | -------------------------------------------------------------- |
| `request`         | [`MonoCloudRequest`](/sdks/nodejs-core/api-reference/types/monocloudrequest)   | MonoCloud request object.                                      |
| `response`        | [`MonoCloudResponse`](/sdks/nodejs-core/api-reference/types/monocloudresponse) | MonoCloud response object.                                     |
| `signOutOptions?` | [`SignOutOptions`](/sdks/nodejs-core/api-reference/types/signoutoptions)       | Configuration for post-logout behavior and federated sign-out. |

#### Returns

`Promise`\<`any`\>

A promise that resolves when the sign-out redirection is initiated.

---

### updateSession()

> **updateSession**(`request`: [`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest), `response`: [`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse), `session`: [`MonoCloudSession`](/sdks/nodejs-core/api-reference/types/monocloudsession)): `Promise`\<`void`\>

Updates the current user's session with new data.

#### Parameters

| Parameter  | Type                                                                                               | Description                            |
| ---------- | -------------------------------------------------------------------------------------------------- | -------------------------------------- |
| `request`  | [`IMonoCloudCookieRequest`](/sdks/nodejs-core/api-reference/types/imonocloudcookierequest)   | MonoCloud cookie request object.       |
| `response` | [`IMonoCloudCookieResponse`](/sdks/nodejs-core/api-reference/types/imonocloudcookieresponse) | MonoCloud cookie response object.      |
| `session`  | [`MonoCloudSession`](/sdks/nodejs-core/api-reference/types/monocloudsession)                 | The updated session object to persist. |

#### Returns

`Promise`\<`void`\>

---

### userInfo()

> **userInfo**(`request`: [`MonoCloudRequest`](/sdks/nodejs-core/api-reference/types/monocloudrequest), `response`: [`MonoCloudResponse`](/sdks/nodejs-core/api-reference/types/monocloudresponse), `userinfoOptions?`: [`UserInfoOptions`](/sdks/nodejs-core/api-reference/types/userinfooptions)): `Promise`\<`any`\>

Retrieves user information, optionally refetching fresh data from the UserInfo endpoint.

#### Parameters

| Parameter          | Type                                                                                 | Description                                             |
| ------------------ | ------------------------------------------------------------------------------------ | ------------------------------------------------------- |
| `request`          | [`MonoCloudRequest`](/sdks/nodejs-core/api-reference/types/monocloudrequest)   | MonoCloud request object.                               |
| `response`         | [`MonoCloudResponse`](/sdks/nodejs-core/api-reference/types/monocloudresponse) | MonoCloud response object.                              |
| `userinfoOptions?` | [`UserInfoOptions`](/sdks/nodejs-core/api-reference/types/userinfooptions)     | Configuration to control refetching and error handling. |

#### Returns

`Promise`\<`any`\>

A promise that resolves with the user information sent as a JSON response.

#### Remarks

If `refresh` is true, the session is updated with fresh claims from the identity provider.
