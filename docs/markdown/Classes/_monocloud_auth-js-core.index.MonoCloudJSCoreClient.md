---
rootSdk: js-core
title: "MonoCloudJSCoreClient"
category: Classes
---

# Class: MonoCloudJSCoreClient

`MonoCloudJSCoreClient` is the core SDK entry point for integrating MonoCloud authentication into single-page applications (SPAs) and other browser-based JavaScript environments.

It provides:

- Redirection and popup-based sign-in and sign-out.
- Session and token management.
- Automatic PKCE and state validation.
- Silent and explicit token refreshing.

## Initialization

```typescript:src/auth.ts
import { MonoCloudJSCoreClient } from '@monocloud/auth-js-core';

export const client = new MonoCloudJSCoreClient({
tenantDomain: 'your-tenant.monocloud.com',
clientId: 'your-client-id',
appUrl: 'http://localhost:3000',
callbackPath: '/callback',
signOutCallbackPath: '/logout'
});
```

## Constructors

### Constructor

> **new MonoCloudJSCoreClient**(`options`: [`MonoCloudJSCoreClientOptions`](/sdks/js-core/api-reference/types/monocloudjscoreclientoptions), `storage`: [`IStorage`](/sdks/js-core/api-reference/types/istorage), `postCallbackFn?`: [`PostCallback`](/sdks/js-core/api-reference/handler-types/postcallback), `onSessionCreating?`: [`OnSessionCreating`](/sdks/js-core/api-reference/handler-types/onsessioncreating)): `MonoCloudJSCoreClient`

Initializes a new instance of the MonoCloudJSCoreClient.

#### Parameters

| Parameter            | Type                                                                                                     | Description                                                                                                      |
| -------------------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `options`            | [`MonoCloudJSCoreClientOptions`](/sdks/js-core/api-reference/types/monocloudjscoreclientoptions) | Configuration options for the client.                                                                            |
| `storage`            | [`IStorage`](/sdks/js-core/api-reference/types/istorage)                                         | Custom storage implementation for session persistence. Defaults to `new LocalStorage()`.                         |
| `postCallbackFn?`    | [`PostCallback`](/sdks/js-core/api-reference/handler-types/postcallback)                     | A callback function executed after a successful sign-in or sign-out. Useful for client-side routing integration. |
| `onSessionCreating?` | [`OnSessionCreating`](/sdks/js-core/api-reference/handler-types/onsessioncreating)           | A hook used to modify or validate the session during creation.                                                   |

#### Returns

`MonoCloudJSCoreClient`

#### Examples

```typescript:src/auth.ts tab="Default Integration" tab-group="constructor"
import { MonoCloudJSCoreClient } from '@monocloud/auth-js-core';

const client = new MonoCloudJSCoreClient({
tenantDomain: 'your-tenant.monocloud.com',
clientId: 'your-client-id',
appUrl: 'http://localhost:3000',
});
```

```typescript:src/auth.ts tab="Custom Storage & Router" tab-group="constructor"
import { MonoCloudJSCoreClient } from '@monocloud/auth-js-core';
import { MemoryStorage } from './storage';
import { router } from './router';

const client = new MonoCloudJSCoreClient(
options,
new MemoryStorage(),
(state) => {
  // Use router to navigate instead of full page reload.
  router.push(state.returnUrl || '/dashboard');
}
);
```

## Properties

| Property                             | Type                                                                          | Description                                                                            |
| ------------------------------------ | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `oidcClient` | [`MonoCloudOidcClient`](/sdks/js-core/api-reference/classes/monocloudoidcclient) | Underlying OpenID Connect client used for advanced authorization and token operations. |

## Methods

### getSession()

> **getSession**(): `Promise`\<[`MonoCloudSession`](/sdks/js-core/api-reference/types/monocloudsession) \| `undefined`\>

Retrieves the current session object from configured storage.

#### Returns

`Promise`\<[`MonoCloudSession`](/sdks/js-core/api-reference/types/monocloudsession) \| `undefined`\>

The active session or `undefined` if not authenticated.

#### Example

```typescript:src/app.ts
const session = await client.getSession();
if (session) {
  console.log('User is logged in:', session.user);
}
```

---

### getTokens()

> **getTokens**(`options?`: [`GetTokensOptions`](/sdks/js-core/api-reference/types/gettokensoptions)): `Promise`\<[`MonoCloudTokens`](/sdks/js-core/api-reference/types/monocloudtokens)\>

Retrieves the active tokens for the session.

If the tokens are expired or about to expire, this method will attempt to refresh them automatically before returning.

#### Parameters

| Parameter  | Type                                                                             | Description                                               |
| ---------- | -------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `options?` | [`GetTokensOptions`](/sdks/js-core/api-reference/types/gettokensoptions) | Options to control token retrieval (e.g., force refresh). |

#### Returns

`Promise`\<[`MonoCloudTokens`](/sdks/js-core/api-reference/types/monocloudtokens)\>

The active tokens.

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
  scopes: 'read:data'
});
```

#### Throws

[MonoCloudValidationError](/sdks/js-core/api-reference/error-classes/monocloudvalidationerror) If the session does not exist.

---

### processCallback()

> **processCallback**(): `Promise`\<`void`\>

Processes the authentication callback.

This method must be called on application startup (usually in the entry point or router)
to handle the response from the identity provider after a redirect flow.

- **Main Window:** Validates the state and code, exchanges them for tokens, and establishes the session.
- **Popup/Iframe:** Posts the callback URL back to the parent/opener window to complete the flow.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the callback processing is complete.

#### Example

```typescript:src/main.ts
import { client } from './auth';

async function init() {
  // Process any pending redirect callbacks before rendering.
  await client.processCallback();

  // Continue mounting the app.
  renderApp();
}

init();
```

---

### refetchUserInfo()

> **refetchUserInfo**(): `Promise`\<`void`\>

Refetches user information from the UserInfo endpoint and updates the local session.

#### Returns

`Promise`\<`void`\>

#### Example

```typescript:src/app.ts
await client.refetchUserInfo();
const session = await client.getSession();
console.log('Updated user data:', session.user);
```

#### Throws

[MonoCloudValidationError](/sdks/js-core/api-reference/error-classes/monocloudvalidationerror) If the session is invalid or the default token is missing.

---

### refreshSession()

> **refreshSession**(`refreshOptions?`: [`RefreshOptions`](/sdks/js-core/api-reference/types/refreshoptions)): `Promise`\<`void`\>

Refreshes the user's session.

This method can be used to explicitly refresh tokens using various methods:

- `silent`: Uses a hidden iframe (requires third-party cookies).
- `refresh_token`: Uses the Refresh Token Grant (requires `offline_access` scope).
- `popup`: Opens a transient popup to refresh the session interactively.

#### Parameters

| Parameter         | Type                                                                         | Description                                  |
| ----------------- | ---------------------------------------------------------------------------- | -------------------------------------------- |
| `refreshOptions?` | [`RefreshOptions`](/sdks/js-core/api-reference/types/refreshoptions) | Optional configuration for the refresh flow. |

#### Returns

`Promise`\<`void`\>

#### Examples

```typescript:src/app.ts tab="Silent (Iframe)" tab-group="refreshSession"
await client.refreshSession({ mode: 'silent' });
```

```typescript:src/app.ts tab="Refresh Token" tab-group="refreshSession"
await client.refreshSession({ mode: 'refresh_token' });
```

#### Throws

[MonoCloudValidationError](/sdks/js-core/api-reference/error-classes/monocloudvalidationerror) If the session is invalid or missing required tokens.

#### Throws

[MonoCloudJsError](/sdks/js-core/api-reference/error-classes/monocloudjserror) If called from within a popup or iframe.

---

### signIn()

> **signIn**(`signInOptions?`: [`SignInOptions`](/sdks/js-core/api-reference/types/signinoptions)): `Promise`\<`void`\>

Initiates the sign-in flow.

#### Parameters

| Parameter        | Type                                                                       | Description                                     |
| ---------------- | -------------------------------------------------------------------------- | ----------------------------------------------- |
| `signInOptions?` | [`SignInOptions`](/sdks/js-core/api-reference/types/signinoptions) | Optional configuration for the sign-in request. |

#### Returns

`Promise`\<`void`\>

#### Examples

```typescript:src/app.ts tab="Redirect Flow" tab-group="signIn"
document.getElementById('login-btn').addEventListener('click', async () => {
  // Standard top-level redirect to the authorization server.
  await client.signIn();
});
```

```typescript:src/app.ts tab="Popup Flow" tab-group="signIn"
document.getElementById('login-popup-btn').addEventListener('click', async () => {
  // Opens a centered popup for authentication.
  await client.signIn({ mode: 'popup' });
  console.log('User finished popup flow!');
});
```

```typescript:src/app.ts tab="Sign Up" tab-group="signIn"
document.getElementById('register-btn').addEventListener('click', async () => {
  // Forces the identity provider to show the registration/sign-up screen.
  await client.signIn({ signUp: true });
});
```

#### Throws

[MonoCloudJsError](/sdks/js-core/api-reference/error-classes/monocloudjserror) If called from within a popup or iframe.

---

### signOut()

> **signOut**(`signOutOptions?`: [`SignOutOptions`](/sdks/js-core/api-reference/types/signoutoptions)): `Promise`\<`void`\>

Initiates the sign-out flow.

Clears the local session and optionally redirects the user to the identity provider to end the session there (Federated Sign-Out).

#### Parameters

| Parameter         | Type                                                                         | Description                                      |
| ----------------- | ---------------------------------------------------------------------------- | ------------------------------------------------ |
| `signOutOptions?` | [`SignOutOptions`](/sdks/js-core/api-reference/types/signoutoptions) | Optional configuration for the sign-out request. |

#### Returns

`Promise`\<`void`\>

#### Examples

```typescript:src/app.ts tab="Redirect Flow" tab-group="signOut"
document.getElementById('logout-btn').addEventListener('click', async () => {
  await client.signOut();
});
```

```typescript:src/app.ts tab="Popup Flow" tab-group="signOut"
document.getElementById('logout-popup-btn').addEventListener('click', async () => {
  // Opens a popup to perform federated sign-out and keep the user on the current page.
  await client.signOut({ mode: 'popup' });
});
```

#### Throws

[MonoCloudJsError](/sdks/js-core/api-reference/error-classes/monocloudjserror) If called from within a popup or iframe.
