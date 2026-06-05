---
rootSdk: React
title: "@monocloud/auth-react"
category: Other
---

# auth-react

<div align="center">
  <a href="https://www.monocloud.com?utm_source=github&utm_medium=auth_js" target="_blank" rel="noopener noreferrer">
    <picture>
      <img src="https://raw.githubusercontent.com/monocloud/auth-js/refs/heads/main/packages/react/banner.svg" alt="MonoCloud Banner">
    </picture>
  </a>
  <div align="right">
    <a href="https://www.npmjs.com/package/@monocloud/auth-react" target="_blank">
      <img src="https://img.shields.io/npm/v/@monocloud/auth-react" alt="NPM" />
    </a>
    <a href="https://opensource.org/licenses/MIT">
      <img src="https://img.shields.io/:license-MIT-blue.svg?style=flat" alt="License: MIT" />
    </a>
    <a href="https://github.com/monocloud/auth-js/actions/workflows/build.yml">
      <img src="https://github.com/monocloud/auth-js/actions/workflows/build.yml/badge.svg" alt="Build Status" />
    </a>
  </div>
</div>

## Introduction

**MonoCloud React Authentication SDK – secure authentication for React single-page applications.**

[MonoCloud](https://www.monocloud.com?utm_source=github&utm_medium=auth_js) is a modern, developer-friendly Identity & Access Management platform.

This SDK provides **React-friendly authentication** for single-page applications. It implements **OAuth 2.0 / OpenID Connect** with **PKCE**, and surfaces authentication state, sign-in and sign-out flows, and route protection through a React provider, hooks, and components.

> This package builds on **`@monocloud/auth-web-js`** and adds React-specific provider, hooks, and components.

## 📘 Documentation

- **Documentation:** [https://www.monocloud.com/docs](https://www.monocloud.com/docs?utm_source=github&utm_medium=auth_js)
- **Quickstart:** [https://www.monocloud.com/docs/quickstarts/react](https://www.monocloud.com/docs/quickstarts/react?utm_source=github&utm_medium=auth_js)
- **SDK Reference:** [https://www.monocloud.com/docs/sdks/react](https://www.monocloud.com/docs/sdks/react/index?utm_source=github&utm_medium=auth_js)
- **API Reference:** [https://monocloud.github.io/auth-js](https://monocloud.github.io/auth-js?utm_source=github&utm_medium=auth_js)

## Supported Platforms

- **React** v18+
- **Modern Browsers** (Chrome, Edge, Firefox, Safari)

## 🚀 Getting Started

### Requirements

- A **MonoCloud Tenant**
- A **Client** configured as a Single Page Application (SPA)
- The application's URL registered in **Callback URLs**, **Sign-out URLs** and **Cross Origin URLs**

## 📦 Installation

```bash
npm install @monocloud/auth-react
```

### Add the Provider

Wrap your application with `<MonoCloudAuthProvider>`.

```tsx
import { MonoCloudAuthProvider } from "@monocloud/auth-react";

export default function Root() {
  return (
    <MonoCloudAuthProvider
      tenantDomain="https://<your-tenant-domain>"
      clientId="<your-client-id>"
    >
      <App />
    </MonoCloudAuthProvider>
  );
}
```

By default the provider automatically processes the OIDC callback when it mounts.

### Access the Authentication State

```tsx
import { useAuth } from "@monocloud/auth-react";

export default function Home() {
  const { isLoading, isAuthenticated, user } = useAuth();

  if (isLoading) return <>Loading…</>;
  if (!isAuthenticated) return <>Not signed in</>;

  return <>Welcome, {user?.email}</>;
}
```

`useAuth()` also exposes the actions `signIn`, `signOut`, `signInSilent`, `refreshSession`, `refetchUserInfo`, and `getTokens`. For lower-level operations use the `useClient()` hook to access the underlying `MonoCloudWebJSClient` client.

### Sign-in, Sign-up and Sign-out

```tsx
import { SignIn, SignUp, SignOut } from '@monocloud/auth-react';

<SignIn>Sign In</SignIn>
<SignUp>Sign Up</SignUp>
<SignOut>Sign Out</SignOut>
```

### Protect Content

```tsx
import { Protected } from "@monocloud/auth-react";

<Protected fallback={<>Sign in to view this.</>}>
  <SecretContent />
</Protected>;
```

> `<Protected>` only affects what is rendered on the client. Always enforce authorization on your APIs as well.

## When should I use `@monocloud/auth-react`?

Use **`@monocloud/auth-react`** if you are building a **React single-page application** and want a secure authentication solution with minimal configuration.

This package is a good fit if you:

- Are building a **React SPA** (Vite, Create React App, and similar)
- Want **authentication state and sign-in / sign-out actions** accessible anywhere in your component tree
- Need to **conditionally render or gate UI** based on the user's authentication status and group membership
- Want **OIDC redirect callbacks handled for you**, with optional client-side-router integration on a dedicated callback route
- Prefer **framework-native ergonomics** without managing the OAuth / OpenID Connect flow yourself

`@monocloud/auth-react` builds on top of **`@monocloud/auth-web-js`**, reusing the same browser implementation (PKCE, redirects, popups, silent refresh, and cross-tab coordination) while providing React-specific ergonomics.

## 🤝 Contributing & Support

### Issues & Feedback

- Use **GitHub Issues** for bug reports and feature requests.
- For tenant or account-specific help, contact MonoCloud Support through your dashboard.

### Security

Do **not** report security issues publicly. Please follow the contact instructions at: [https://www.monocloud.com/contact](https://www.monocloud.com/contact?utm_source=github&utm_medium=auth_js)

## 📄 License

Licensed under the **MIT License**. See the included [`LICENSE`](https://github.com/monocloud/auth-js/blob/main/LICENSE) file.

## Classes

- [LocalStorage](/sdks/react/api-reference/classes/localstorage)
- [MemoryStorage](/sdks/react/api-reference/classes/memorystorage)
- [MonoCloudWebJSClient](/sdks/react/api-reference/classes/monocloudwebjsclient)
- [SessionStorage](/sdks/react/api-reference/classes/sessionstorage)

## Components

- [MonoCloudAuthProvider](/sdks/react/api-reference/components/monocloudauthprovider)
- [ProcessCallback](/sdks/react/api-reference/components/processcallback)
- [Protected](/sdks/react/api-reference/components/protected)
- [SignIn](/sdks/react/api-reference/components/signin)
- [SignOut](/sdks/react/api-reference/components/signout)
- [SignUp](/sdks/react/api-reference/components/signup)

## Error Classes

- [MonoCloudAuthBaseError](/sdks/react/api-reference/error-classes/monocloudauthbaseerror)
- [MonoCloudHttpError](/sdks/react/api-reference/error-classes/monocloudhttperror)
- [MonoCloudJsError](/sdks/react/api-reference/error-classes/monocloudjserror)
- [MonoCloudOPError](/sdks/react/api-reference/error-classes/monocloudoperror)
- [MonoCloudTokenError](/sdks/react/api-reference/error-classes/monocloudtokenerror)
- [MonoCloudValidationError](/sdks/react/api-reference/error-classes/monocloudvalidationerror)

## Hooks

- [useAuth](/sdks/react/api-reference/hooks/useauth)
- [useClient](/sdks/react/api-reference/hooks/useclient)

## Types

- [AccessToken](/sdks/react/api-reference/types/accesstoken)
- [Address](/sdks/react/api-reference/types/address)
- [ApplicationState](/sdks/react/api-reference/types/applicationstate)
- [AuthorizationParams](/sdks/react/api-reference/types/authorizationparams)
- [AuthState](/sdks/react/api-reference/types/authstate)
- [CallbackState](/sdks/react/api-reference/types/callbackstate)
- [DefaultAuthParams](/sdks/react/api-reference/types/defaultauthparams)
- [GetTokensOptions](/sdks/react/api-reference/types/gettokensoptions)
- [Group](/sdks/react/api-reference/types/group)
- [IdTokenClaims](/sdks/react/api-reference/types/idtokenclaims)
- [Indicator](/sdks/react/api-reference/types/indicator)
- [IStorage](/sdks/react/api-reference/types/istorage)
- [Jwk](/sdks/react/api-reference/types/jwk)
- [MonoCloudAuth](/sdks/react/api-reference/types/monocloudauth)
- [MonoCloudAuthProviderProps](/sdks/react/api-reference/types/monocloudauthproviderprops)
- [MonoCloudSession](/sdks/react/api-reference/types/monocloudsession)
- [MonoCloudTokens](/sdks/react/api-reference/types/monocloudtokens)
- [MonoCloudUser](/sdks/react/api-reference/types/monoclouduser)
- [MonoCloudWebJSClientOptions](/sdks/react/api-reference/types/monocloudwebjsclientoptions)
- [ProcessCallbackProps](/sdks/react/api-reference/types/processcallbackprops)
- [ProtectedComponentProps](/sdks/react/api-reference/types/protectedcomponentprops)
- [RefreshGrantOptions](/sdks/react/api-reference/types/refreshgrantoptions)
- [RefreshOptions](/sdks/react/api-reference/types/refreshoptions)
- [SignInOptions](/sdks/react/api-reference/types/signinoptions)
- [SignInProps](/sdks/react/api-reference/types/signinprops)
- [SignInSilentOptions](/sdks/react/api-reference/types/signinsilentoptions)
- [SignOutOptions](/sdks/react/api-reference/types/signoutoptions)
- [SignOutProps](/sdks/react/api-reference/types/signoutprops)
- [SignUpProps](/sdks/react/api-reference/types/signupprops)
- [UserinfoResponse](/sdks/react/api-reference/types/userinforesponse)

## Types (Enums)

- [Authenticators](/sdks/react/api-reference/enums/authenticators)
- [ClientAuthMethod](/sdks/react/api-reference/enums/clientauthmethod)
- [CodeChallengeMethod](/sdks/react/api-reference/enums/codechallengemethod)
- [DisplayOptions](/sdks/react/api-reference/enums/displayoptions)
- [InteractionMode](/sdks/react/api-reference/enums/interactionmode)
- [Prompt](/sdks/react/api-reference/enums/prompt)
- [ResponseModes](/sdks/react/api-reference/enums/responsemodes)
- [ResponseTypes](/sdks/react/api-reference/enums/responsetypes)
- [SecurityAlgorithms](/sdks/react/api-reference/enums/securityalgorithms)

## Types (Handler)

- [OnSessionCreating](/sdks/react/api-reference/handler-types/onsessioncreating)
- [PostCallback](/sdks/react/api-reference/handler-types/postcallback)
