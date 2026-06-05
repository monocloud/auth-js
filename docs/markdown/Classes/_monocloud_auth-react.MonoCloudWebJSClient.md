---
rootSdk: React
title: "MonoCloudWebJSClient"
category: Classes
description: "MonoCloudWebJSClient is the core SDK entry point for integrating MonoCloud authentication into single-page applications (SPAs) and other browser-based JavaScript environments."
---

# Class: MonoCloudWebJSClient

`MonoCloudWebJSClient` is the core SDK entry point for integrating MonoCloud
authentication into single-page applications (SPAs) and other browser-based
JavaScript environments.

Features:

- Redirect and popup sign-in / sign-out flows.
- Silent sign-in via a hidden iframe (`prompt=none`) for restoring SSO sessions at app bootstrap.
- Refresh Token Grant based session refreshing.
- Session and token storage with pluggable storage adapters.
- Automatic PKCE, state, and nonce generation and validation.

## Initialization

```typescript:src/auth.ts
import { MonoCloudWebJSClient } from '@monocloud/auth-web-js';

export const client = new MonoCloudWebJSClient({
  tenantDomain: 'https://<your-tenant>',
  clientId: '<your-client-id>',
});
```

## Constructors

### Constructor

> **new MonoCloudWebJSClient**(`options`: [`MonoCloudWebJSClientOptions`](/sdks/react/api-reference/types/monocloudwebjsclientoptions)): `MonoCloudWebJSClient`

Initializes a new instance of MonoCloudWebJSClient.

#### Parameters

| Parameter | Type                                                                                           | Description                           |
| --------- | ---------------------------------------------------------------------------------------------- | ------------------------------------- |
| `options` | [`MonoCloudWebJSClientOptions`](/sdks/react/api-reference/types/monocloudwebjsclientoptions) | Configuration options for the client. |

#### Returns

`MonoCloudWebJSClient`

#### Examples

```typescript:src/auth.ts tab="Default Integration" tab-group="constructor"
import { MonoCloudWebJSClient } from '@monocloud/auth-web-js';

export const client = new MonoCloudWebJSClient({
  tenantDomain: 'https://<your-tenant>',
  clientId: '<your-client-id>',
});
```

```typescript:src/auth.ts tab="Custom Storage & Router" tab-group="constructor"
import { MonoCloudWebJSClient, MemoryStorage } from '@monocloud/auth-web-js';
import { router } from './router';

export const client = new MonoCloudWebJSClient({
  tenantDomain: 'https://<your-tenant>',
  clientId: '<your-client-id>',
  storage: new MemoryStorage(),
  postCallback: state => {
    router.push(state.returnUrl ?? '/dashboard');
  },
});
```

## Properties

| Property                             | Type                                                                       | Description                                                                                                                                                                                   |
| ------------------------------------ | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `oidcClient` | [`MonoCloudOidcClient`](/sdks/nodejs/api-reference/classes/monocloudoidcclient) | Underlying OpenID Connect client used for advanced authorization and token operations. Use this when you need lower-level access to OIDC protocol operations not directly exposed by the SDK. |

## Methods

### getSession()

> **getSession**(): `Promise`\<[`MonoCloudSession`](/sdks/react/api-reference/types/monocloudsession) \| `undefined`\>

Retrieves the current session object from the configured storage.

#### Returns

`Promise`\<[`MonoCloudSession`](/sdks/react/api-reference/types/monocloudsession) \| `undefined`\>

The active session, or `undefined` if not authenticated.

#### Example

```typescript:src/app.ts
const session = await client.getSession();
if (session) {
  console.log('User is logged in:', session.user);
}
```

---

### getTokens()

> **getTokens**(`options?`: [`GetTokensOptions`](/sdks/react/api-reference/types/gettokensoptions)): `Promise`\<[`MonoCloudTokens`](/sdks/react/api-reference/types/monocloudtokens)\>

Retrieves the active tokens for the current session.

If the access token is expired (or about to expire), this method automatically attempts to refresh it using the Refresh Token Grant before returning.

#### Parameters

| Parameter  | Type                                                                     | Description                                                             |
| ---------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| `options?` | [`GetTokensOptions`](/sdks/react/api-reference/types/gettokensoptions) | Options that control token retrieval (force refresh, scopes, resource). |

#### Returns

`Promise`\<[`MonoCloudTokens`](/sdks/react/api-reference/types/monocloudtokens)\>

The active tokens for the requested resource and scopes.

#### Examples

```typescript:src/app.ts tab="Default Tokens" tab-group="getTokens"
const tokens = await client.getTokens();
console.log(tokens.accessToken);
```

```typescript:src/app.ts tab="Force Refresh" tab-group="getTokens"
const tokens = await client.getTokens({ forceRefresh: true });
```

```typescript:src/app.ts tab="Specific Resource" tab-group="getTokens"
const tokens = await client.getTokens({
  resource: 'https://api.example.com',
  scopes: 'read:data',
});
```

#### Throws

[MonoCloudValidationError](/sdks/react/api-reference/error-classes/monocloudvalidationerror) If no session exists or the access token cannot be located.

---

### processCallback()

> **processCallback**(): `Promise`\<`void`\>

Processes the authentication callback from the authorization server.

Call this once on application startup (typically in your entry point or
router). It inspects the current URL together with the persisted callback
state and automatically completes a pending sign-in or sign-out flow -
there is no need to dispatch on the route yourself.

#### Returns

`Promise`\<`void`\>

A promise that resolves when callback processing is complete.

#### Example

```typescript:src/main.ts
async function init() {
  // Complete any pending redirect callback before rendering.
  await client.processCallback();

  // Continue mounting the app.
}

init();
```

---

### refetchUserInfo()

> **refetchUserInfo**(): `Promise`\<`void`\>

Refetches user information from the UserInfo endpoint and updates the local session.

The default access token (matching the client's configured default resource and authorized scopes) is used to call the UserInfo endpoint.

#### Returns

`Promise`\<`void`\>

#### Example

```typescript:src/app.ts
await client.refetchUserInfo();
const session = await client.getSession();
console.log('Updated user data:', session?.user);
```

#### Throws

[MonoCloudValidationError](/sdks/react/api-reference/error-classes/monocloudvalidationerror) If the session is invalid or the default access token is missing.

---

### refreshSession()

> **refreshSession**(`refreshOptions?`: [`RefreshOptions`](/sdks/react/api-reference/types/refreshoptions)): `Promise`\<`void`\>

Refreshes the current user's session using the OAuth 2.0 Refresh Token Grant.

Requires a session that includes a refresh token (obtained by including the `offline_access` scope at sign-in).

To start a fresh, non-interactive authorization (for example, on app bootstrap when there is no local session yet) use [signInSilent()](#signinsilent) instead.

#### Parameters

| Parameter         | Type                                                                 | Description                                  |
| ----------------- | -------------------------------------------------------------------- | -------------------------------------------- |
| `refreshOptions?` | [`RefreshOptions`](/sdks/react/api-reference/types/refreshoptions) | Optional configuration for the refresh flow. |

#### Returns

`Promise`\<`void`\>

A promise that resolves when the session has been refreshed.

#### Examples

```typescript:src/app.ts tab="Default" tab-group="refreshSession"
await client.refreshSession();
```

```typescript:src/app.ts tab="Resource-Scoped Refresh" tab-group="refreshSession"
await client.refreshSession({
  refreshGrantOptions: {
    resource: 'https://api.example.com',
    scopes: 'read:data',
  },
});
```

#### Throws

[MonoCloudValidationError](/sdks/react/api-reference/error-classes/monocloudvalidationerror) If the session is invalid or missing a refresh token.

---

### signIn()

> **signIn**(`signInOptions?`: [`SignInOptions`](/sdks/react/api-reference/types/signinoptions)): `Promise`\<`void`\>

Initiates the sign-in flow.

#### Parameters

| Parameter        | Type                                                               | Description                                     |
| ---------------- | ------------------------------------------------------------------ | ----------------------------------------------- |
| `signInOptions?` | [`SignInOptions`](/sdks/react/api-reference/types/signinoptions) | Optional configuration for the sign-in request. |

#### Returns

`Promise`\<`void`\>

#### Examples

```typescript:src/app.ts tab="Redirect Flow" tab-group="signIn"
await client.signIn();
```

```typescript:src/app.ts tab="Popup Flow" tab-group="signIn"
await client.signIn({ mode: 'popup' });
```

```typescript:src/app.ts tab="Sign Up" tab-group="signIn"
await client.signIn({ signUp: true });
```

---

### signInSilent()

> **signInSilent**(`signInSilentOptions?`: [`SignInSilentOptions`](/sdks/react/api-reference/types/signinsilentoptions)): `Promise`\<[`MonoCloudSession`](/sdks/react/api-reference/types/monocloudsession)\>

Attempts to silently sign the user in using a hidden iframe and `prompt=none`.

Useful for restoring a session at app bootstrap when the user is signed in at MonoCloud but no local session exists yet (for example, after opening a new tab or a hard refresh that cleared in-memory storage).

The method runs a full authorization round-trip through a hidden iframe. If MonoCloud has a valid session it resolves to the new session. Otherwise it rejects with a [MonoCloudOPError](/sdks/react/api-reference/error-classes/monocloudoperror).

#### Parameters

| Parameter              | Type                                                                           | Description                                            |
| ---------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------ |
| `signInSilentOptions?` | [`SignInSilentOptions`](/sdks/react/api-reference/types/signinsilentoptions) | Optional configuration for the silent sign-in request. |

#### Returns

`Promise`\<[`MonoCloudSession`](/sdks/react/api-reference/types/monocloudsession)\>

The newly established session.

#### Example

```typescript:src/app.ts
import { MonoCloudOPError } from '@monocloud/auth-web-js';

try {
  const session = await client.signInSilent();
  console.log('Restored session for:', session.user);
} catch (error) {
  if (error instanceof MonoCloudOPError && error.error === 'login_required') {
    console.log('Not signed in');
  } else {
    throw error;
  }
}
```

#### Throws

[MonoCloudOPError](/sdks/react/api-reference/error-classes/monocloudoperror) If the authorization server cannot satisfy the request - for example, because the user has no IdP session (`login_required`) or interaction is otherwise required.

#### Throws

[MonoCloudJsError](/sdks/react/api-reference/error-classes/monocloudjserror) If the iframe cannot be created (for example, in a cross-origin-isolated context) or the authentication window times out.

---

### signOut()

> **signOut**(`signOutOptions?`: [`SignOutOptions`](/sdks/react/api-reference/types/signoutoptions)): `Promise`\<`void`\>

Initiates the sign-out flow.

Clears the local session and, when `federatedSignOut` is enabled, also signs the user out of MonoCloud (Single Sign-Out).

#### Parameters

| Parameter         | Type                                                                 | Description                                      |
| ----------------- | -------------------------------------------------------------------- | ------------------------------------------------ |
| `signOutOptions?` | [`SignOutOptions`](/sdks/react/api-reference/types/signoutoptions) | Optional configuration for the sign-out request. |

#### Returns

`Promise`\<`void`\>

A promise that resolves when the sign-out flow has been initiated (redirect mode) or completed (popup mode).

#### Examples

```typescript:src/app.ts tab="Redirect Flow" tab-group="signOut"
await client.signOut();
```

```typescript:src/app.ts tab="Popup Flow" tab-group="signOut"
await client.signOut({ mode: 'popup' });
```
