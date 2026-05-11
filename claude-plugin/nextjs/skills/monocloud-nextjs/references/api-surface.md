# API surface — `@monocloud/auth-nextjs`

Exhaustive export list per subpath, verified against `packages/nextjs/src/`. Signatures are condensed; protection-helper option types are in `protecting.md`.

## `@monocloud/auth-nextjs` (root)

### Functions

| Export | Signature (summary) |
|---|---|
| `authMiddleware` | `(options?) => NextMiddleware \| NextProxy` — also callable as `(req, evt) => Promise<NextMiddlewareResult>` for composition |
| `monoCloudAuth` | `(options?) => MonoCloudAuthHandler` — catch-all route handler factory; use only when you can't use `authMiddleware()` |
| `getSession` | `() / (req) / (req, res) / (req, res, options)` → `Promise<MonoCloudSession \| undefined>` |
| `getTokens` | Same overload shape as `getSession` → `Promise<MonoCloudTokens>`; throws `MonoCloudValidationError` if no session |
| `isAuthenticated` | `() / (req, res?)` → `Promise<boolean>` |
| `isUserInGroup` | `(groups[]) / (req, groups[]) / (req, res, groups[])` → `Promise<boolean>` |
| `protect` | `(options?) => Promise<void>` — App Router only; redirects if not authenticated/authorized |
| `protectApi` | `(handler, options?)` — wraps an App Router or Pages Router handler |
| `protectPage` | `(component, options?)` (App Router) **or** `(options?)` (Pages Router — returns `getServerSideProps`) |
| `redirectToSignIn` | `(options?) => Promise<void>` — App Router only |
| `redirectToSignOut` | `(options?) => Promise<void>` — App Router only |

### Class

```ts
class MonoCloudNextClient {
  constructor(options?: MonoCloudOptions);
  readonly coreClient: MonoCloudCoreClient;     // framework-agnostic client
  readonly oidcClient: MonoCloudOidcClient;     // raw OIDC client

  // Same methods as the function exports above:
  authMiddleware(...): ...;
  monoCloudAuth(options?): MonoCloudAuthHandler;
  getSession(...): Promise<MonoCloudSession | undefined>;
  getTokens(...): Promise<MonoCloudTokens>;
  isAuthenticated(...): Promise<boolean>;
  isUserInGroup(...): Promise<boolean>;
  protect(options?): Promise<void>;
  protectApi(handler, options?): handler;
  protectPage(componentOrOptions, options?): handler;
  redirectToSignIn(options?): Promise<void>;
  redirectToSignOut(options?): Promise<void>;
}
```

Use the class when you need multiple configurations, dependency injection, or explicit lifecycle control. Otherwise prefer the function exports (they share a lazily-initialized singleton).

### Errors (re-exported from `@monocloud/auth-node-core`)

- `MonoCloudAuthBaseError`
- `MonoCloudValidationError`
- `MonoCloudHttpError`
- `MonoCloudOPError`
- `MonoCloudTokenError`

### Types

**SDK-defined (`./types`)**:

`MonoCloudAuthOptions`, `MonoCloudMiddlewareOptions`, `MonoCloudAuthHandler`, `NextMiddlewareResult`, `NextMiddlewareOnAccessDenied`, `NextMiddlewareOnGroupAccessDenied`, `ProtectedRoutes`, `ProtectedRouteMatcher`, `CustomProtectedRouteMatcher`, `OnError`, `AppOnError`, `PageOnError`, `AppRouterContext`, `AppRouterApiHandlerFn`, `AppRouterPageHandler`, `ExtraAuthParams`, `GroupOptions`, `IsUserInGroupOptions`, `ProtectOptions`, `RedirectToSignInOptions`, `RedirectToSignOutOptions`, `ProtectApiAppOptions`, `ProtectApiPageOptions`, `ProtectAppPageOptions`, `ProtectPagePageOptions`, `ProtectPagePageReturnType`, `ProtectPagePageOnAccessDeniedType`, `ProtectPagePageOnGroupAccessDeniedType`, `ProtectPageGetServerSidePropsContext`, `ProtectedAppServerComponent`, `ProtectedAppServerComponentProps`, `AppRouterApiOnAccessDeniedHandler`, `AppRouterApiOnGroupAccessDeniedHandler`, `PageRouterApiOnAccessDeniedHandler`, `PageRouterApiOnGroupAccessDeniedHandler`.

**Re-exported from `@monocloud/auth-node-core`**:

`MonoCloudOptions`, `MonoCloudSession`, `MonoCloudUser`, `MonoCloudTokens`, `AccessToken`, `GetSessionOptions`, `GetTokensOptions`, `ApplicationState`, `MonoCloudRequest`, `Indicator`, `MonoCloudSessionOptions`, `MonoCloudSessionOptionsBase`, `MonoCloudSessionStore`, `MonoCloudCookieOptions`, `SessionLifetime`, `SameSiteValues`, `UserinfoResponse`, `Address`, `Authenticators`, `DisplayOptions`, `AuthorizationParams`, `MonoCloudRoutes`, `MonoCloudStateOptions`, `MonoCloudStatePartialOptions`, `IdTokenClaims`, `Group`, `Jwk`, `Prompt`, `CodeChallengeMethod`, `ResponseTypes`, `ResponseModes`, `SecurityAlgorithms`, `OnSessionCreating`, `OnBackChannelLogout`, `OnSetApplicationState`.

## `@monocloud/auth-nextjs/client`

```ts
// Hook
function useAuth(): AuthenticationState;

interface AuthenticationState {
  isLoading: boolean;
  isAuthenticated: boolean;
  error?: Error;
  user?: MonoCloudUser;
  refetch: (refresh?: boolean) => void;   // refresh=true forces a userinfo refresh
}

// HOC
function protectClientPage<P>(
  Component: ComponentType<P & { user: MonoCloudUser }>,
  options?: ProtectClientPageOptions,
): React.FC<P>;

interface ProtectClientPageOptions {
  returnUrl?: string;
  groups?: string[];
  groupsClaim?: string;
  matchAll?: boolean;
  authParams?: ExtraAuthParams;
  onAccessDenied?: () => React.ReactNode;
  onGroupAccessDenied?: (user: MonoCloudUser) => React.ReactNode;
  onError?: (error: Error) => React.ReactNode;
}
```

`useAuth()` requires no provider. It fetches `process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_USER_INFO_URL ?? '/api/auth/userinfo'` via SWR.

## `@monocloud/auth-nextjs/components`

Server-or-client safe components that render as `<a>` tags. All accept arbitrary `<a>` props in addition to those listed.

```ts
function SignIn(props: SignInProps & React.AnchorHTMLAttributes<HTMLAnchorElement>): JSX.Element;
interface SignInProps extends ExtraAuthParams {
  children: React.ReactNode;
  returnUrl?: string;
}

function SignUp(props: SignUpProps & React.AnchorHTMLAttributes<HTMLAnchorElement>): JSX.Element;
interface SignUpProps extends Omit<ExtraAuthParams, 'authenticatorHint' | 'loginHint' | 'prompt'> {
  returnUrl?: string;
  // children is part of the AnchorHTMLAttributes intersection
}

function SignOut(props: SignOutProps & React.AnchorHTMLAttributes<HTMLAnchorElement>): JSX.Element;
interface SignOutProps {
  children: React.ReactNode;
  postLogoutUrl?: string;
  federated?: boolean;
}
```

`<SignUp>` is implemented as a `<SignIn>` with `prompt=create` baked in — that's why it omits the params that would conflict with sign-up.

## `@monocloud/auth-nextjs/components/client`

Client-only components.

```ts
function RedirectToSignIn(props: RedirectToSignInProps): null;
interface RedirectToSignInProps extends ExtraAuthParams {
  returnUrl?: string;
}

function Protected(props: ProtectedComponentProps): React.ReactNode | null;
interface ProtectedComponentProps {
  children: React.ReactNode;
  groups?: string[];
  groupsClaim?: string;
  matchAllGroups?: boolean;             // note: not `matchAll`
  fallback?: React.ReactNode;
  onGroupAccessDenied?: (user: MonoCloudUser) => React.ReactNode;
}
```

## Default auth routes

| Logical route | Default path | Override env | Public mirror (for client components) |
|---|---|---|---|
| Sign-in | `/api/auth/signin` | `MONOCLOUD_AUTH_SIGNIN_URL` | `NEXT_PUBLIC_MONOCLOUD_AUTH_SIGNIN_URL` |
| Callback | `/api/auth/callback` | `MONOCLOUD_AUTH_CALLBACK_URL` | `NEXT_PUBLIC_MONOCLOUD_AUTH_CALLBACK_URL` |
| Userinfo | `/api/auth/userinfo` | `MONOCLOUD_AUTH_USER_INFO_URL` | `NEXT_PUBLIC_MONOCLOUD_AUTH_USER_INFO_URL` |
| Sign-out | `/api/auth/signout` | `MONOCLOUD_AUTH_SIGNOUT_URL` | `NEXT_PUBLIC_MONOCLOUD_AUTH_SIGNOUT_URL` |
| Back-channel logout | `/api/auth/backchannel-logout` | `MONOCLOUD_AUTH_BACK_CHANNEL_LOGOUT_URL` | n/a |

Any `NEXT_PUBLIC_MONOCLOUD_AUTH_*` variable is also copied into its private counterpart at client init, so you only need to set the `NEXT_PUBLIC_` form when you want both the server middleware and the client helpers to agree on a custom path.

## Default option values

From `packages/node-core/src/options/defaults.ts`:

```ts
{
  routes: {
    callback: '/api/auth/callback',
    backChannelLogout: '/api/auth/backchannel-logout',
    signIn: '/api/auth/signin',
    signOut: '/api/auth/signout',
    userInfo: '/api/auth/userinfo',
  },
  clockSkew: 60,                         // seconds
  responseTimeout: 10000,                // ms
  usePar: false,
  fetchUserInfo: true,
  refetchUserInfo: false,
  federatedSignOut: true,
  defaultAuthParams: { scopes: 'openid profile email', responseType: 'code' },
  allowQueryParamOverrides: true,
  strictProfileSync: false,
  session: {
    cookie: { httpOnly: true, name: 'session', path: '/', sameSite: 'lax', persistent: true },
    sliding: false,
    duration: 24 * 60 * 60,              // 1 day
    maximumDuration: 7 * 24 * 60 * 60,   // 7 days
  },
  state: {
    cookie: { httpOnly: true, name: 'state', path: '/', sameSite: 'lax', persistent: false },
  },
  idTokenSigningAlg: 'RS256',
}
```
