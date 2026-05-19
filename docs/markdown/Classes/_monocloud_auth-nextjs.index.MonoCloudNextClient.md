---
rootSdk: Next.js
title: "MonoCloudNextClient"
category: Classes
description: "MonoCloudNextClient is the core SDK entry point for integrating MonoCloud authentication into a Next.js application."
---

# Class: MonoCloudNextClient

`MonoCloudNextClient` is the core SDK entry point for integrating MonoCloud authentication into a Next.js application.

It provides:

- Authentication middleware
- Route protection helpers
- Session and token access
- Redirect utilities
- Server-side enforcement helpers

## 1. Add environment variables

```bash:.env.local
MONOCLOUD_AUTH_TENANT_DOMAIN=<tenant-domain>
MONOCLOUD_AUTH_CLIENT_ID=<client-id>
MONOCLOUD_AUTH_CLIENT_SECRET=<client-secret>
MONOCLOUD_AUTH_SCOPES=openid profile email
MONOCLOUD_AUTH_APP_URL=http://localhost:3000
MONOCLOUD_AUTH_COOKIE_SECRET=<cookie-secret>
```

## 2. Register middleware

```typescript:src/proxy.ts
import { authMiddleware } from "@monocloud/auth-nextjs";

export default authMiddleware();

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
};
```

## Advanced usage

### Create a shared client instance

By default, the SDK exposes function exports (for example, `authMiddleware()`, `getSession()`, `getTokens()`) that internally use a shared singleton `MonoCloudNextClient`.

Create your own `MonoCloudNextClient` instance when you need multiple configurations, dependency injection, or explicit control over initialization.

```ts:src/monocloud.ts
import { MonoCloudNextClient } from "@monocloud/auth-nextjs";

export const monoCloud = new MonoCloudNextClient();
```

### Using instance methods

Once you create a client instance, call methods directly on it instead of using the default function exports.

```ts:src/app/page.tsx
import { monoCloud } from "@/monocloud";

export default async function Page() {
  const session = await monoCloud.getSession();

  if (!session) {
    return <>Not signed in</>;
  }

  return <>Hello {session.user.name}</>;
}
```

#### Using constructor options

When configuration is provided through both constructor options and environment variables, the values passed to the constructor take precedence. Environment variables are used only for options that are not explicitly supplied.

```ts:src/monocloud.ts
import { MonoCloudNextClient } from "@monocloud/auth-nextjs";

export const monoCloud = new MonoCloudNextClient({
  tenantDomain: "<tenant-domain>",
  clientId: "<client-id>",
  clientSecret: "<client-secret>",
  appUrl: "http://localhost:3000",
  cookieSecret: "<cookie-secret>",
  defaultAuthParams: {
    scopes: "openid profile email",
  },
});
```

### Modifying default routes

If you customize any of the default auth route paths:

- Also set the corresponding `NEXT_PUBLIC_` environment variables so client-side helpers
  (for example `<SignIn />`, `<SignOut />`, and `useAuth()`) can discover the correct URLs.
- Update the **Application URLs** in your MonoCloud Dashboard to match the new paths.

Example:

```bash:.env.local
MONOCLOUD_AUTH_CALLBACK_URL=/api/custom_callback
NEXT_PUBLIC_MONOCLOUD_AUTH_CALLBACK_URL=/api/custom_callback
```

When routes are overridden, the Redirect URI configured in the dashboard
must reflect the new path. For example, during local development:

`http://localhost:3000/api/custom_callback`

## Constructors

### Constructor

> **new MonoCloudNextClient**(`options?`: [`MonoCloudOptions`](/sdks/nextjs/api-reference/types/monocloudoptions)): `MonoCloudNextClient`

Creates a new client instance.

#### Parameters

| Parameter  | Type                                                                            | Description                                                                                                                                    |
| ---------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `options?` | [`MonoCloudOptions`](/sdks/nextjs/api-reference/types/monocloudoptions) | Optional configuration for initializing the MonoCloud client. If not provided, settings are automatically resolved from environment variables. |

#### Returns

`MonoCloudNextClient`

## Accessors

### coreClient

#### Get Signature

> **get** **coreClient**(): [`MonoCloudCoreClient`](/sdks/nodejs-core/api-reference/classes/monocloudcoreclient)

This exposes the framework-agnostic MonoCloud client used internally by the Next.js SDK.
Use it if you need access to lower-level functionality not directly exposed by MonoCloudNextClient.

##### Returns

[`MonoCloudCoreClient`](/sdks/nodejs-core/api-reference/classes/monocloudcoreclient)

Returns the underlying **Node client** instance.

---

### oidcClient

#### Get Signature

> **get** **oidcClient**(): [`MonoCloudOidcClient`](/sdks/nodejs/api-reference/classes/monocloudoidcclient)

This is intended for advanced scenarios requiring direct control over the authorization or token flow.

##### Returns

[`MonoCloudOidcClient`](/sdks/nodejs/api-reference/classes/monocloudoidcclient)

Returns the underlying **OIDC client** used for OpenID Connect operations.

## Methods

### authMiddleware()

#### Call Signature

> **authMiddleware**(`options?`: [`MonoCloudMiddlewareOptions`](/sdks/nextjs/api-reference/types/monocloudmiddlewareoptions)): `NextMiddleware`

##### Parameters

| Parameter  | Type                                                                                                | Description                                                                                                                                                           |
| ---------- | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `options?` | [`MonoCloudMiddlewareOptions`](/sdks/nextjs/api-reference/types/monocloudmiddlewareoptions) | Optional configuration that controls how authentication is enforced (for example, redirect behavior, route matching, or custom handling of unauthenticated requests). |

##### Returns

`NextMiddleware`

Returns a Next.js middleware result (`NextResponse`, redirect, or `undefined` to continue processing).

##### See

[authMiddleware](/sdks/nextjs/api-reference/functions/authmiddleware) for full docs and examples.

#### Call Signature

> **authMiddleware**(`request`: `NextRequest`, `event`: `NextFetchEvent`): [`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult) \| `Promise`\<[`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult)\>

##### Parameters

| Parameter | Type             | Description                                                               |
| --------- | ---------------- | ------------------------------------------------------------------------- |
| `request` | `NextRequest`    | Incoming Next.js middleware request used to resolve authentication state. |
| `event`   | `NextFetchEvent` | Next.js middleware event providing lifecycle hooks such as `waitUntil`.   |

##### Returns

[`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult) \| `Promise`\<[`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult)\>

Returns a Next.js middleware result (`NextResponse`, redirect, or `undefined` to continue processing).

##### See

[authMiddleware](/sdks/nextjs/api-reference/functions/authmiddleware) for full docs and examples.

---

### getSession()

#### Call Signature

> **getSession**(`options?`: [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions)): `Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

##### Parameters

| Parameter  | Type                                                                              | Description                                                    |
| ---------- | --------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `options?` | [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions) | Optional configuration controlling session retrieval behavior. |

##### Returns

`Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

Returns the resolved session, or `undefined` if none exists.

##### See

[getSession](/sdks/nextjs/api-reference/functions/getsession) for full docs and examples.

#### Call Signature

> **getSession**(`req`: `Request` \| `NextRequest`, `options?`: [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions)): `Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

##### Parameters

| Parameter  | Type                                                                              | Description                                                                                             |
| ---------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `req`      | `Request` \| `NextRequest`                                                        | Incoming request used to read authentication cookies and headers to resolve the current user's session. |
| `options?` | [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions) | Optional configuration controlling session retrieval behavior.                                          |

##### Returns

`Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

Returns the resolved session, or `undefined` if none exists.

##### See

[getSession](/sdks/nextjs/api-reference/functions/getsession) for full docs and examples.

#### Call Signature

> **getSession**(`req`: `Request` \| `NextRequest`, `res`: `Response` \| `NextResponse`\<`unknown`\>, `options?`: [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions)): `Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

##### Parameters

| Parameter  | Type                                                                              | Description                                                                                             |
| ---------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `req`      | `Request` \| `NextRequest`                                                        | Incoming request used to read authentication cookies and headers to resolve the current user's session. |
| `res`      | `Response` \| `NextResponse`\<`unknown`\>                                         | Optional response to update if session resolution requires refreshed authentication cookies or headers. |
| `options?` | [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions) | Optional configuration controlling session retrieval behavior.                                          |

##### Returns

`Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

Returns the resolved session, or `undefined` if none exists.

##### See

[getSession](/sdks/nextjs/api-reference/functions/getsession) for full docs and examples.

#### Call Signature

> **getSession**(`req`: `NextApiRequest` \| `IncomingMessage`, `res`: `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>, `options?`: [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions)): `Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

##### Parameters

| Parameter  | Type                                                                              | Description                                                                                          |
| ---------- | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `req`      | `NextApiRequest` \| `IncomingMessage`                                             | Incoming Node.js request used to read authentication cookies and resolve the current user's session. |
| `res`      | `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>                        | Outgoing Node.js response used to apply refreshed authentication cookies when required.              |
| `options?` | [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions) | Optional configuration controlling session retrieval behavior.                                       |

##### Returns

`Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

Returns the resolved session, or `undefined` if none exists.

##### See

[getSession](/sdks/nextjs/api-reference/functions/getsession) for full docs and examples.

---

### getTokens()

#### Call Signature

> **getTokens**(`options?`: [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions)): `Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

##### Parameters

| Parameter  | Type                                                                            | Description                                                                       |
| ---------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `options?` | [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions) | Optional configuration controlling refresh behavior and resource/scope selection. |

##### Returns

`Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

The current user's tokens, refreshed if necessary.

##### See

[getTokens](/sdks/nextjs/api-reference/functions/gettokens) for full docs and examples.

##### Throws

[MonoCloudValidationError](/sdks/nextjs/api-reference/error-classes/monocloudvalidationerror) If no valid session exists.

#### Call Signature

> **getTokens**(`req`: `Request` \| `NextRequest`, `options?`: [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions)): `Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

##### Parameters

| Parameter  | Type                                                                            | Description                                                                       |
| ---------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `req`      | `Request` \| `NextRequest`                                                      | Incoming request used to resolve authentication from cookies and headers.         |
| `options?` | [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions) | Optional configuration controlling refresh behavior and resource/scope selection. |

##### Returns

`Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

The current user's tokens, refreshed if necessary.

##### See

[getTokens](/sdks/nextjs/api-reference/functions/gettokens) for full docs and examples.

##### Throws

[MonoCloudValidationError](/sdks/nextjs/api-reference/error-classes/monocloudvalidationerror) If no valid session exists.

#### Call Signature

> **getTokens**(`req`: `Request` \| `NextRequest`, `res`: `Response` \| `NextResponse`\<`unknown`\>, `options?`: [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions)): `Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

##### Parameters

| Parameter  | Type                                                                            | Description                                                                       |
| ---------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `req`      | `Request` \| `NextRequest`                                                      | Incoming request used to resolve authentication from cookies and headers.         |
| `res`      | `Response` \| `NextResponse`\<`unknown`\>                                       | Existing response to update with refreshed authentication cookies or headers.     |
| `options?` | [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions) | Optional configuration controlling refresh behavior and resource/scope selection. |

##### Returns

`Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

The current user's tokens, refreshed if necessary.

##### See

[getTokens](/sdks/nextjs/api-reference/functions/gettokens) for full docs and examples.

##### Throws

[MonoCloudValidationError](/sdks/nextjs/api-reference/error-classes/monocloudvalidationerror) If no valid session exists.

#### Call Signature

> **getTokens**(`req`: `NextApiRequest` \| `IncomingMessage`, `res`: `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>, `options?`: [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions)): `Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

##### Parameters

| Parameter  | Type                                                                            | Description                                                                             |
| ---------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `req`      | `NextApiRequest` \| `IncomingMessage`                                           | Incoming Node.js request used to resolve authentication from cookies.                   |
| `res`      | `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>                      | Outgoing Node.js response used to apply refreshed authentication cookies when required. |
| `options?` | [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions) | Optional configuration controlling refresh behavior and resource/scope selection.       |

##### Returns

`Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

The current user's tokens, refreshed if necessary.

##### See

[getTokens](/sdks/nextjs/api-reference/functions/gettokens) for full docs and examples.

##### Throws

[MonoCloudValidationError](/sdks/nextjs/api-reference/error-classes/monocloudvalidationerror) If no valid session exists.

---

### isAuthenticated()

#### Call Signature

> **isAuthenticated**(): `Promise`\<`boolean`\>

##### Returns

`Promise`\<`boolean`\>

Returns `true` if a valid session exists; otherwise `false`.

##### See

[isAuthenticated](/sdks/nextjs/api-reference/functions/isauthenticated) for full docs and examples.

#### Call Signature

> **isAuthenticated**(`req`: `Request` \| `NextRequest`, `res?`: `Response` \| `NextResponse`\<`unknown`\>): `Promise`\<`boolean`\>

##### Parameters

| Parameter | Type                                      | Description                                                                              |
| --------- | ----------------------------------------- | ---------------------------------------------------------------------------------------- |
| `req`     | `Request` \| `NextRequest`                | Incoming request used to resolve authentication from cookies and headers.                |
| `res?`    | `Response` \| `NextResponse`\<`unknown`\> | Optional response to update if refreshed authentication cookies or headers are required. |

##### Returns

`Promise`\<`boolean`\>

Returns `true` if a valid session exists; otherwise `false`.

##### See

[isAuthenticated](/sdks/nextjs/api-reference/functions/isauthenticated) for full docs and examples.

#### Call Signature

> **isAuthenticated**(`req`: `NextApiRequest` \| `IncomingMessage`, `res`: `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>): `Promise`\<`boolean`\>

##### Parameters

| Parameter | Type                                                       | Description                                                                             |
| --------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `req`     | `NextApiRequest` \| `IncomingMessage`                      | Incoming Node.js request used to resolve authentication from cookies.                   |
| `res`     | `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\> | Outgoing Node.js response used to apply refreshed authentication cookies when required. |

##### Returns

`Promise`\<`boolean`\>

Returns `true` if a valid session exists; otherwise `false`.

##### See

[isAuthenticated](/sdks/nextjs/api-reference/functions/isauthenticated) for full docs and examples.

---

### isUserInGroup()

#### Call Signature

> **isUserInGroup**(`groups`: `string`[], `options?`: [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions)): `Promise`\<`boolean`\>

##### Parameters

| Parameter  | Type                                                                                    | Description                                                           |
| ---------- | --------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `groups`   | `string`[]                                                                              | Group IDs or names to check against the user's group memberships.     |
| `options?` | [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions) | Optional configuration controlling how group membership is evaluated. |

##### Returns

`Promise`\<`boolean`\>

Returns `true` if the user belongs to at least one specified group; otherwise `false`.

##### See

[isUserInGroup](/sdks/nextjs/api-reference/functions/isuseringroup) for full docs and examples.

#### Call Signature

> **isUserInGroup**(`req`: `Request` \| `NextRequest`, `groups`: `string`[], `options?`: [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions)): `Promise`\<`boolean`\>

##### Parameters

| Parameter  | Type                                                                                    | Description                                                               |
| ---------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `req`      | `Request` \| `NextRequest`                                                              | Incoming request used to resolve authentication from cookies and headers. |
| `groups`   | `string`[]                                                                              | Group IDs or names to check against the user's group memberships.         |
| `options?` | [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions) | Optional configuration controlling how group membership is evaluated.     |

##### Returns

`Promise`\<`boolean`\>

Returns `true` if the user belongs to at least one specified group; otherwise `false`.

##### See

[isUserInGroup](/sdks/nextjs/api-reference/functions/isuseringroup) for full docs and examples.

#### Call Signature

> **isUserInGroup**(`req`: `Request` \| `NextRequest`, `res`: `Response` \| `NextResponse`\<`unknown`\>, `groups`: `string`[], `options?`: [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions)): `Promise`\<`boolean`\>

##### Parameters

| Parameter  | Type                                                                                    | Description                                                                                 |
| ---------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `req`      | `Request` \| `NextRequest`                                                              | Incoming request used to resolve authentication from cookies and headers.                   |
| `res`      | `Response` \| `NextResponse`\<`unknown`\>                                               | Existing response to update with refreshed authentication cookies or headers when required. |
| `groups`   | `string`[]                                                                              | Group IDs or names to check against the user's group memberships.                           |
| `options?` | [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions) | Optional configuration controlling how group membership is evaluated.                       |

##### Returns

`Promise`\<`boolean`\>

Returns `true` if the user belongs to at least one specified group; otherwise `false`.

##### See

[isUserInGroup](/sdks/nextjs/api-reference/functions/isuseringroup) for full docs and examples.

#### Call Signature

> **isUserInGroup**(`req`: `NextApiRequest` \| `IncomingMessage`, `res`: `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>, `groups`: `string`[], `options?`: [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions)): `Promise`\<`boolean`\>

##### Parameters

| Parameter  | Type                                                                                    | Description                                                                             |
| ---------- | --------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `req`      | `NextApiRequest` \| `IncomingMessage`                                                   | Incoming Node.js request used to resolve authentication from cookies.                   |
| `res`      | `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>                              | Outgoing Node.js response used to apply refreshed authentication cookies when required. |
| `groups`   | `string`[]                                                                              | Group IDs or names to check against the user's group memberships.                       |
| `options?` | [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions) | Optional configuration controlling how group membership is evaluated.                   |

##### Returns

`Promise`\<`boolean`\>

Returns `true` if the user belongs to at least one specified group; otherwise `false`.

##### See

[isUserInGroup](/sdks/nextjs/api-reference/functions/isuseringroup) for full docs and examples.

---

### monoCloudAuth()

> **monoCloudAuth**(`options?`: [`MonoCloudAuthOptions`](/sdks/nextjs/api-reference/types/monocloudauthoptions)): [`MonoCloudAuthHandler`](/sdks/nextjs/api-reference/handler-types/monocloudauthhandler)

#### Parameters

| Parameter  | Type                                                                                    | Description                                  |
| ---------- | --------------------------------------------------------------------------------------- | -------------------------------------------- |
| `options?` | [`MonoCloudAuthOptions`](/sdks/nextjs/api-reference/types/monocloudauthoptions) | Optional configuration for the auth handler. |

#### Returns

[`MonoCloudAuthHandler`](/sdks/nextjs/api-reference/handler-types/monocloudauthhandler)

Returns a Next.js-compatible handler for App Router route handlers or Pages Router API routes.

#### See

[monoCloudAuth](/sdks/nextjs/api-reference/functions/monocloudauth) for full docs and examples.

---

### protect()

> **protect**(`options?`: [`ProtectOptions`](/sdks/nextjs/api-reference/types/protectoptions)): `Promise`\<`void`\>

#### Parameters

| Parameter  | Type                                                                        | Description                                                                                   |
| ---------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `options?` | [`ProtectOptions`](/sdks/nextjs/api-reference/types/protectoptions) | Optional configuration for redirect behavior (for example, return URL or sign-in parameters). |

#### Returns

`Promise`\<`void`\>

Resolves if the user is authenticated; otherwise triggers a redirect.

#### See

[protect](/sdks/nextjs/api-reference/functions/protect) for full docs and examples.

---

### protectApi()

#### Call Signature

> **protectApi**(`handler`: [`AppRouterApiHandlerFn`](/sdks/nextjs/api-reference/handler-types/approuterapihandlerfn), `options?`: [`ProtectApiAppOptions`](/sdks/nextjs/api-reference/types/protectapiappoptions)): [`AppRouterApiHandlerFn`](/sdks/nextjs/api-reference/handler-types/approuterapihandlerfn)

##### Parameters

| Parameter  | Type                                                                                                  | Description                                                                   |
| ---------- | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `handler`  | [`AppRouterApiHandlerFn`](/sdks/nextjs/api-reference/handler-types/approuterapihandlerfn) | The route handler to protect.                                                 |
| `options?` | [`ProtectApiAppOptions`](/sdks/nextjs/api-reference/types/protectapiappoptions)               | Optional configuration controlling authentication and authorization behavior. |

##### Returns

[`AppRouterApiHandlerFn`](/sdks/nextjs/api-reference/handler-types/approuterapihandlerfn)

Returns a wrapped handler that enforces authentication (and optional authorization) before invoking the original handler.

##### See

[protectApi](#protectapi) for full docs and examples.

#### Call Signature

> **protectApi**(`handler`: `NextApiHandler`, `options?`: [`ProtectApiPageOptions`](/sdks/nextjs/api-reference/types/protectapipageoptions)): `NextApiHandler`

##### Parameters

| Parameter  | Type                                                                                      | Description                                                                   |
| ---------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `handler`  | `NextApiHandler`                                                                          | The route handler to protect.                                                 |
| `options?` | [`ProtectApiPageOptions`](/sdks/nextjs/api-reference/types/protectapipageoptions) | Optional configuration controlling authentication and authorization behavior. |

##### Returns

`NextApiHandler`

Returns a wrapped handler that enforces authentication (and optional authorization) before invoking the original handler.

##### See

[protectApi](#protectapi) for full docs and examples.

---

### protectPage()

#### Call Signature

> **protectPage**(`component`: [`ProtectedAppServerComponent`](/sdks/nextjs/api-reference/handler-types/protectedappservercomponent), `options?`: [`ProtectAppPageOptions`](/sdks/nextjs/api-reference/types/protectapppageoptions)): [`AppRouterPageHandler`](/sdks/nextjs/api-reference/handler-types/approuterpagehandler)

##### Parameters

| Parameter   | Type                                                                                                              | Description                                                                                                                     |
| ----------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `component` | [`ProtectedAppServerComponent`](/sdks/nextjs/api-reference/handler-types/protectedappservercomponent) | The App Router server component to protect.                                                                                     |
| `options?`  | [`ProtectAppPageOptions`](/sdks/nextjs/api-reference/types/protectapppageoptions)                         | Optional configuration for authentication, authorization, and custom access handling (`onAccessDenied`, `onGroupAccessDenied`). |

##### Returns

[`AppRouterPageHandler`](/sdks/nextjs/api-reference/handler-types/approuterpagehandler)

A wrapped page component that enforces authentication before rendering.

##### See

[protectPage](/sdks/nextjs/api-reference/functions/protectpage) for full docs and examples.

#### Call Signature

> **protectPage**\<`P`, `Q`\>(`options?`: [`ProtectPagePageOptions`](/sdks/nextjs/api-reference/types/protectpagepageoptions)\<`P`, `Q`\>): [`ProtectPagePageReturnType`](/sdks/nextjs/api-reference/handler-types/protectpagepagereturntype)\<`P`, `Q`\>

##### Type Parameters

| Type Parameter                            | Description                               |
| ----------------------------------------- | ----------------------------------------- |
| `P` _extends_ `Record`\<`string`, `any`\> | Props returned from `getServerSideProps`. |
| `Q` _extends_ `ParsedUrlQuery`            | Query parameters parsed from the URL.     |

##### Parameters

| Parameter  | Type                                                                                                    | Description                                                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `options?` | [`ProtectPagePageOptions`](/sdks/nextjs/api-reference/types/protectpagepageoptions)\<`P`, `Q`\> | Optional configuration for authentication, authorization, and custom access handling (`onAccessDenied`, `onGroupAccessDenied`). |

##### Returns

[`ProtectPagePageReturnType`](/sdks/nextjs/api-reference/handler-types/protectpagepagereturntype)\<`P`, `Q`\>

A getServerSideProps wrapper that enforces authentication before executing the page logic.

##### See

[protectPage](/sdks/nextjs/api-reference/functions/protectpage) for full docs and examples.

---

### redirectToSignIn()

> **redirectToSignIn**(`options?`: [`RedirectToSignInOptions`](/sdks/nextjs/api-reference/types/redirecttosigninoptions)): `Promise`\<`void`\>

#### Parameters

| Parameter  | Type                                                                                          | Description                                                                                    |
| ---------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `options?` | [`RedirectToSignInOptions`](/sdks/nextjs/api-reference/types/redirecttosigninoptions) | Optional configuration for the redirect, such as `returnUrl` or additional sign-in parameters. |

#### Returns

`Promise`\<`void`\>

Never resolves. Triggers a redirect to the sign-in flow.

#### See

[redirectToSignIn](/sdks/nextjs/api-reference/functions/redirecttosignin) for full docs and examples.

---

### redirectToSignOut()

> **redirectToSignOut**(`options?`: [`RedirectToSignOutOptions`](/sdks/nextjs/api-reference/types/redirecttosignoutoptions)): `Promise`\<`void`\>

#### Parameters

| Parameter  | Type                                                                                            | Description                                                                                                 |
| ---------- | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `options?` | [`RedirectToSignOutOptions`](/sdks/nextjs/api-reference/types/redirecttosignoutoptions) | Optional configuration for the redirect, such as `postLogoutRedirectUri` or additional sign-out parameters. |

#### Returns

`Promise`\<`void`\>

Never resolves. Triggers a redirect to the sign-out flow.

#### See

[redirectToSignOut](/sdks/nextjs/api-reference/functions/redirecttosignout) for full docs and examples.
