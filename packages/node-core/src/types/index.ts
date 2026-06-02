import type {
  AccessToken,
  AuthorizationParams,
  AuthState,
  EndSessionParameters,
  IdTokenClaims,
  MonoCloudSession,
  RefreshGrantOptions,
  SecurityAlgorithms,
  UserinfoResponse,
} from '@monocloud/auth-core';
import { MonoCloudRequest } from './internal';

/**
 * Allowed values for the cookie `SameSite` attribute.
 *
 * The `SameSite` setting controls when cookies are included in cross-site requests and helps protect against cross-site request forgery (CSRF) attacks.
 *
 * @category Types (Enums)
 */
export type SameSiteValues =
  /**
   * Cookies are only sent for same-site requests.
   *
   * Cookies will NOT be included in cross-site navigations, redirects, or embedded requests.
   *
   * Provides the strongest CSRF protection but may break authentication flows that rely on cross-site redirects.
   */
  | 'strict'

  /**
   * Cookies are sent for same-site requests and top-level cross-site navigations (for example, following a link).
   *
   * This is the recommended default for most authentication flows.
   */
  | 'lax'

  /**
   * Cookies are sent with all requests, including cross-site requests.
   *
   * Must be used together with `Secure=true` (HTTPS only).
   *
   * Required for some third-party or cross-origin authentication scenarios.
   */
  | 'none';

/**
 * Represents the lifetime metadata associated with a user session.
 *
 * The properties use short keys to minimize cookie and storage size, since this structure may be serialized as part of session data.
 *
 * All timestamps are expressed as **Unix epoch time (seconds)**.
 *
 * @category Types
 */
export interface SessionLifetime {
  /**
   * Session creation time.
   *
   * The moment the session was initially established.
   */
  c: number;

  /**
   * Last updated time.
   *
   * Updated whenever the session is refreshed or extended (for example, during sliding expiration).
   */
  u: number;

  /**
   * Optional expiration time.
   */
  e?: number;
}

/**
 * Represents the authentication transaction state used during the authorization flow.
 *
 * This state is created before redirecting the user to MonoCloud and is validated when the user returns to the application during the callback.
 */
export interface MonoCloudState extends AuthState {
  /**
   * Custom application state associated with the authentication request.
   *
   * This value is preserved across the redirect to MonoCloud and restored after authentication completes.
   */
  appState: string;

  /**
   * Optional return URL.
   *
   * If provided, the user will be redirected to this URL after authentication completes successfully.
   */
  returnUrl?: string;
}

/**
 * Defines a storage adapter used to persist authentication sessions.
 *
 * Implement this interface to store sessions outside the default cookie-based storage — for example in Redis, a database, or a distributed cache.
 *
 * @category Types
 */
export interface MonoCloudSessionStore {
  /**
   * Retrieves a session associated with the provided key.
   *
   * @param key Unique identifier of the session.
   * @returns Returns the stored session, or `undefined` / `null` if no session exists.
   */
  get(key: string): Promise<MonoCloudSession | undefined | null>;

  /**
   * Persists or updates a session.
   *
   * The provided lifetime information can be used by the store to configure TTL/expiration policies.
   *
   * @param key Unique identifier of the session.
   * @param data The session data to persist.
   * @param lifetime Session lifetime metadata (creation, update, expiration).
   */
  set(
    key: string,
    data: MonoCloudSession,
    lifetime: SessionLifetime
  ): Promise<void>;

  /**
   * Removes a session from the store.
   *
   * @param key Unique identifier of the session to delete.
   */
  delete(key: string): Promise<void>;
}

/**
 * Configuration options for authentication cookies.
 *
 * These settings control how MonoCloud session and state cookies are created, scoped, and transmitted by the browser.
 *
 * @category Types
 */
export interface MonoCloudCookieOptions {
  /**
   * The cookie name. Defaults to `"session"` for session cookies and `"state"` for state cookies.
   */
  name: string;

  /**
   * The URL path for which the cookie is valid.
   *
   * @defaultValue '/'
   */
  path: string;

  /**
   * Optional domain scope for the cookie.
   */
  domain?: string;

  /**
   * Indicates whether the cookie is accessible only via HTTP requests. Helps mitigate XSS attacks by preventing client-side JavaScript access.
   *
   * Always enforced as `true` for state cookies.
   *
   * @defaultValue true
   */
  httpOnly: boolean;

  /**
   * Indicates whether the cookie should only be transmitted over HTTPS.
   *
   * If not explicitly provided, this value is automatically inferred from the application URL scheme.
   */
  secure: boolean;

  /**
   * The SameSite policy applied to the cookie. Controls cross-site request behavior and CSRF protection.
   *
   * @defaultValue 'lax'
   */
  sameSite: SameSiteValues;

  /**
   * Determines whether the cookie persists across browser restarts.
   * Defaults to `true` for session cookies and `false` for state cookies.
   */
  persistent: boolean;
}

/**
 * Configuration options for authentication sessions.
 *
 * These options control how user sessions are created, persisted, and expired.
 *
 * @category Types
 */
export interface MonoCloudSessionOptionsBase {
  /**
   * Configuration for the session cookie used to identify the user session.
   */
  cookie: MonoCloudCookieOptions;

  /**
   * Enables sliding session expiration.
   *
   * When enabled, the session expiration is extended on active requests, up to the configured `maximumDuration`.
   *
   * When disabled, the session expires after a fixed duration regardless of user activity.
   *
   * @defaultValue false
   */
  sliding: boolean;

  /**
   * The session lifetime in seconds.
   *
   * With **absolute sessions** (`sliding = false`), this defines the total session lifetime.
   * With **sliding sessions**, this defines the idle timeout before the session expires.
   *
   * @defaultValue 86400 (1 Day)
   */
  duration: number;

  /**
   * The absolute maximum lifetime of a sliding session in seconds.
   *
   * This value limits how long a session can exist even if the user remains continuously active.
   *
   * Only applies when `sliding` is enabled.
   *
   * @defaultValue 604800 (7 days)
   */
  maximumDuration: number;

  /**
   * Optional session store used to persist session data.
   *
   * If not provided, The SDK uses the default cookie-based session storage.
   *
   * Custom stores allow centralized session management (e.g. Redis, database).
   */
  store?: MonoCloudSessionStore;
}

/**
 * Partial configuration options for authentication state handling.
 *
 * @category Types
 */
export interface MonoCloudStatePartialOptions {
  /**
   * Partial configuration for the state cookie.
   *
   * This cookie temporarily stores authorization transaction data required to validate the callback response and prevent replay or CSRF attacks.
   */
  cookie?: Partial<MonoCloudCookieOptions>;
}

/**
 * Configuration options for authentication state handling.
 *
 * @category Types
 */
export interface MonoCloudStateOptions {
  /**
   * Configuration for the state cookie.
   *
   * This cookie temporarily stores authorization transaction data required to validate the callback response and prevent replay or CSRF attacks.
   */
  cookie: MonoCloudCookieOptions;
}

/**
 * Route configuration for MonoCloud authentication handlers.
 *
 * These routes define the internal application endpoints used by the SDK to process authentication flows such as sign-in, callback handling, sign-out, and user profile retrieval.
 *
 * You typically do not need to change these values unless you want to customize your application's authentication URLs.
 *
 * > When customizing routes, ensure the corresponding URLs are also configured in your MonoCloud Dashboard and exposed to the client using the matching environment variables.
 *
 * @category Types
 */
export interface MonoCloudRoutes {
  /**
   * Route that receives the authorization callback from MonoCloud after a successful authentication.
   *
   * @defaultValue '/api/auth/callback'
   */
  callback: string;

  /**
   * Route that handles OpenID Connect back-channel logout requests initiated by MonoCloud.
   *
   * @defaultValue '/api/auth/backchannel-logout'
   */
  backChannelLogout: string;

  /**
   * Route used to initiate the sign-in flow.
   *
   * @defaultValue '/api/auth/signin'
   */
  signIn: string;

  /**
   * Route used to initiate the sign-out flow.
   *
   * @defaultValue '/api/auth/signout'
   */
  signOut: string;

  /**
   * Route that exposes the authenticated user's profile information.
   *
   * @defaultValue '/api/auth/userinfo'
   */
  userInfo: string;
}

/**
 * Represents an additional resource indicator that can be requested during token acquisition.
 *
 * Resource indicators allow an access token to be scoped to a specific API or service (audience). Multiple indicators may be provided when requesting tokens for different protected resources.
 *
 * @category Types
 */
export interface Indicator {
  /**
   * Space-separated list of resource identifiers (audiences) that the access token should be issued for.
   *
   * Each value typically represents an API identifier or resource URI.
   */
  resource: string;

  /**
   * Optional. Space-separated list of scopes to request specifically for this resource.
   */
  scopes?: string;
}

/**
 * Core configuration options for the SDK.
 *
 * These options define how the SDK communicates with your MonoCloud tenant, manages sessions, and performs authentication flows.
 *
 * @category Types
 */
export interface MonoCloudOptionsBase {
  /**
   * Client identifier of the application registered in MonoCloud.
   */
  clientId: string;

  /**
   * Optional client secret used for confidential clients.
   */
  clientSecret?: string;

  /**
   * MonoCloud tenant domain (for example, `https://your-tenant.us.monocloud.com`).
   */
  tenantDomain: string;

  /**
   * Secret used to encrypt and sign authentication cookies. This value should be long, random, and kept private.
   */
  cookieSecret: string;

  /**
   * Base URL where the application is hosted.
   *
   * Used to construct redirect URLs and validate requests.
   */
  appUrl: string;

  /**
   * Route paths used by MonoCloud authentication handlers.
   */
  routes: MonoCloudRoutes;

  /**
   * Allowed clock skew (in seconds) when validating token timestamps.
   *
   * @defaultValue 0 (seconds)
   */
  clockSkew: number;

  /**
   * Additional time tolerance (in seconds) applied when validating time-based token claims (such as `exp` and `nbf`).
   *
   * @defaultValue 60 (seconds)
   */
  clockTolerance: number;

  /**
   * Maximum time (in milliseconds) to wait for responses from the MonoCloud authorization server.
   *
   * @defaultValue 10000 (10 seconds)
   */
  responseTimeout: number;

  /**
   * Enables Pushed Authorization Requests (PAR).
   *
   * When enabled, authorization parameters are sent securely via the PAR endpoint instead of the browser.
   *
   * @defaultValue false
   */
  usePar: boolean;

  /**
   * URL to redirect users to after logout completes.
   */
  postLogoutRedirectUri?: string;

  /**
   * When `true`, signing out also logs the user out of MonoCloud (Single Sign-Out).
   *
   * @defaultValue true
   */
  federatedSignOut: boolean;

  /**
   * Fetch user profile data from the `UserInfo` endpoint after authentication completes.
   *
   * @defaultValue true
   */
  fetchUserInfo: boolean;

  /**
   * Refetch user profile data whenever the application's `UserInfo` endpoint is invoked.
   *
   * @defaultValue false
   */
  refetchUserInfo: boolean;

  /**
   * Default authorization parameters included in authentication requests.
   *
   * @defaultValue {
   *   scope: 'openid email profile',
   *   response_type: 'code'
   * }
   */
  defaultAuthParams: AuthorizationParams;

  /**
   * Optional resource indicators available when requesting tokens via `getTokens()`.
   *
   */
  resources?: Indicator[];

  /**
   * Session configuration.
   */
  session: MonoCloudSessionOptionsBase;

  /**
   * Authentication state configuration.
   */
  state: MonoCloudStateOptions;

  /**
   * Expected signing algorithm for ID tokens.
   *
   * @defaultValue 'RS256'
   */
  idTokenSigningAlg: SecurityAlgorithms;

  /**
   *  List of ID token claims that should be removed before storing data in the session.
   */
  filteredIdTokenClaims: string[];

  /**
   * Identifier used for internal debugging/logging.
   */
  debugger: string;

  /**
   * Custom User-Agent value sent with requests to MonoCloud.
   */
  userAgent: string;

  /**
   * Duration (in seconds) to cache the JWKS document.
   *
   * @defaultValue 300
   */
  jwksCacheDuration?: number;

  /**
   * Duration (in seconds) to cache OpenID discovery metadata.
   *
   * @defaultValue 300
   */
  metadataCacheDuration?: number;

  /**
   * Allows authorization parameters to be overridden using query parameters.
   *
   * When disabled, parameters such as `scope`, `resource`, `prompt`, and `login_hint` present in the request URL are ignored and cannot modify the authentication request.
   *
   * @defaultValue false
   */
  allowQueryParamOverrides?: boolean;

  /**
   * Determines how user profile is updated when the session is updated.
   *
   * When enabled, the session user profile is fully replaced with a newly constructed profile
   * derived from the latest ID token and, if applicable, the UserInfo response.
   *
   * @defaultValue false
   */
  strictProfileSync?: boolean;

  /**
   * Invoked when a back-channel logout request is received.
   */
  onBackChannelLogout?: OnBackChannelLogout;

  /**
   * Invoked before authentication begins to attach custom application state.
   */
  onSetApplicationState?: OnSetApplicationState;

  /**
   * Invoked before a session is created or updated. Can be used to modify session data or attach custom fields.
   */
  onSessionCreating?: OnSessionCreating;
}

/**
 * Partial configuration options for authentication sessions.
 *
 * @category Types
 */
export interface MonoCloudSessionOptions extends Partial<
  Omit<MonoCloudSessionOptionsBase, 'store' | 'cookie'>
> {
  /**
   * Session cookie settings.
   */
  cookie?: Partial<MonoCloudCookieOptions>;

  /**
   * A custom session store implementation.
   *
   * When provided, sessions are persisted using this store instead of cookies-only storage.
   */
  store?: MonoCloudSessionStore;
}

/**
 * Configuration options used to initialize the SDK client.
 *
 * ## Configuration Sources
 *
 * Configuration values can be provided using either:
 *
 * - **Constructor options** - passed when creating the client instance.
 * - **Environment variables** - using `MONOCLOUD_AUTH_*` variables.
 *
 * When both are provided, **constructor options override environment variables**.
 *
 * ## Environment Variables
 *
 * ### Core Configuration (Required)
 *
 * | Environment Variable | Description |
 * |----------------------|-------------|
 * | `MONOCLOUD_AUTH_CLIENT_ID` | Unique identifier for your application/client. |
 * | `MONOCLOUD_AUTH_CLIENT_SECRET` | Application/client secret used for authentication. |
 * | `MONOCLOUD_AUTH_TENANT_DOMAIN` | The domain of your MonoCloud tenant (for example, `https://your-tenant.us.monocloud.com`). |
 * | `MONOCLOUD_AUTH_APP_URL` | The base URL where your application is hosted. |
 * | `MONOCLOUD_AUTH_COOKIE_SECRET` | A long, random string used to encrypt and sign session cookies. |
 *
 * ### Authentication & Security
 *
 * | Environment Variable | Description |
 * |----------------------|-------------|
 * | `MONOCLOUD_AUTH_SCOPES` | Space-separated list of OIDC scopes to request (for example, `openid profile email`). |
 * | `MONOCLOUD_AUTH_RESOURCE` | Default resource (audience) identifier used when issuing access tokens. |
 * | `MONOCLOUD_AUTH_USE_PAR` | Enables Pushed Authorization Requests (PAR) for authorization flows. |
 * | `MONOCLOUD_AUTH_CLOCK_SKEW` | Allowed clock drift (in seconds) when validating token timestamps. |
 * | `MONOCLOUD_AUTH_CLOCK_TOLERANCE` | Additional time tolerance (in seconds) applied when validating time-based token claims. |
 * | `MONOCLOUD_AUTH_FEDERATED_SIGNOUT` | If `true`, signing out of the application also signs the user out of MonoCloud (SSO sign-out). |
 * | `MONOCLOUD_AUTH_RESPONSE_TIMEOUT` | Maximum time (in milliseconds) to wait for responses from the authentication service. |
 * | `MONOCLOUD_AUTH_ALLOW_QUERY_PARAM_OVERRIDES` | Allows authorization parameters (such as `scope`, `resource`, or `prompt`) to be overridden via URL query parameters. |
 * | `MONOCLOUD_AUTH_POST_LOGOUT_REDIRECT_URI` | URL users are redirected to after a successful logout. |
 * | `MONOCLOUD_AUTH_FETCH_USER_INFO` | Determines whether user profile data is fetched from the `UserInfo` endpoint after authorization. |
 * | `MONOCLOUD_AUTH_REFETCH_USER_INFO` | If `true`, user information is re-fetched on each userinfo request. |
 * | `MONOCLOUD_AUTH_ID_TOKEN_SIGNING_ALG` | Expected signing algorithm for ID tokens (for example, `RS256`). |
 * | `MONOCLOUD_AUTH_FILTERED_ID_TOKEN_CLAIMS` | Space-separated list of ID token claims excluded from the session object. |
 *
 *  ### Routes
 *
 * | Environment Variable | Description |
 * |----------------------|-------------|
 * | `MONOCLOUD_AUTH_CALLBACK_URL` | Application path where the authorization server redirects the user after authentication. |
 * | `MONOCLOUD_AUTH_SIGNIN_URL` | Internal route used to initiate the sign-in flow. |
 * | `MONOCLOUD_AUTH_SIGNOUT_URL` | Internal route used to initiate the sign-out flow. |
 * | `MONOCLOUD_AUTH_USER_INFO_URL` | Route that exposes the authenticated user’s profile retrieved from the UserInfo endpoint. |
 *
 * ### Session Cookie Settings
 *
 * | Environment Variable | Description |
 * |----------------------|-------------|
 * | `MONOCLOUD_AUTH_SESSION_COOKIE_NAME` | Name of the cookie used to store the authenticated user session. |
 * | `MONOCLOUD_AUTH_SESSION_COOKIE_PATH` | Path scope for which the session cookie is valid. |
 * | `MONOCLOUD_AUTH_SESSION_COOKIE_DOMAIN` | Domain scope for which the session cookie is valid. |
 * | `MONOCLOUD_AUTH_SESSION_COOKIE_HTTP_ONLY` | Prevents client-side scripts from accessing the session cookie. |
 * | `MONOCLOUD_AUTH_SESSION_COOKIE_SECURE` | Ensures the session cookie is only sent over HTTPS connections. |
 * | `MONOCLOUD_AUTH_SESSION_COOKIE_SAME_SITE` | SameSite policy applied to the session cookie (`lax`, `strict`, or `none`). |
 * | `MONOCLOUD_AUTH_SESSION_COOKIE_PERSISTENT` | Determines whether the session cookie persists across browser restarts. |
 * | `MONOCLOUD_AUTH_SESSION_SLIDING` | Enables sliding session expiration instead of absolute expiration. |
 * | `MONOCLOUD_AUTH_SESSION_DURATION` | Session lifetime in seconds. |
 * | `MONOCLOUD_AUTH_SESSION_MAX_DURATION` | Maximum allowed lifetime of a sliding session in seconds. |
 *
 * ### State Cookie Settings
 *
 * | Environment Variable | Description |
 * |----------------------|-------------|
 * | `MONOCLOUD_AUTH_STATE_COOKIE_NAME` | Name of the cookie used to store OpenID Connect state and nonce values during authentication. |
 * | `MONOCLOUD_AUTH_STATE_COOKIE_PATH` | Path scope for which the state cookie is valid. |
 * | `MONOCLOUD_AUTH_STATE_COOKIE_DOMAIN` | Domain scope for which the state cookie is valid. |
 * | `MONOCLOUD_AUTH_STATE_COOKIE_SECURE` | Ensures the state cookie is only sent over HTTPS connections. |
 * | `MONOCLOUD_AUTH_STATE_COOKIE_SAME_SITE` | SameSite policy applied to the state cookie (`lax`, `strict`, or `none`). |
 * | `MONOCLOUD_AUTH_STATE_COOKIE_PERSISTENT` | Determines whether the state cookie persists beyond the current browser session. |
 *
 * ### Caching
 *
 * | Environment Variable | Description |
 * |----------------------|-------------|
 * | `MONOCLOUD_AUTH_JWKS_CACHE_DURATION` | Duration (in seconds) to cache the JSON Web Key Set (JWKS) used to verify tokens. |
 * | `MONOCLOUD_AUTH_METADATA_CACHE_DURATION` | Duration (in seconds) to cache the OpenID Connect discovery metadata. |
 *
 * @category Types
 */
export interface MonoCloudOptions extends Partial<
  Omit<
    MonoCloudOptionsBase,
    'defaultAuthParams' | 'session' | 'routes' | 'state'
  >
> {
  /**
   * Default authorization parameters automatically included in authentication requests unless explicitly overridden.
   *
   * @defaultValue {
   *   scope: 'openid email profile',
   *   response_type: 'code'
   * }
   */
  defaultAuthParams?: AuthorizationParams;

  /**
   * Overrides for built-in authentication route paths.
   */
  routes?: Partial<MonoCloudRoutes>;

  /**
   * Session configuration overrides.
   */
  session?: MonoCloudSessionOptions;

  /**
   * Configuration for authentication state handling.
   */
  state?: MonoCloudStatePartialOptions;
}

/**
 * Callback invoked when a back-channel logout event is received from the authorization server.
 *
 * Back-channel logout allows MonoCloud to notify the application that a user session should be terminated without browser interaction.
 *
 * @category Types (Handler)
 *
 * @param sub Optional subject identifier (`sub`) of the user associated with the logout event.
 * @param sid Optional session identifier (`sid`) for the session being terminated.
 * @returns Returns a promise or void. Execution completes once logout handling finishes.
 */
export type OnBackChannelLogout = (
  /**
   * Subject identifier of the user.
   */
  sub?: string,

  /**
   * Session identifier associated with the logout event.
   */
  sid?: string
) => Promise<void> | void;

/**
 * Represents custom application state associated with an authentication request.
 *
 * This object is populated via `onSetApplicationState` and is persisted through the authentication flow. The resolved value is later available during session creation and can be used to carry application-specific context (for example: return targets, workflow state, or tenant hints).
 *
 * @category Types
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface ApplicationState extends Record<string, any> {}

/**
 * Callback invoked before a session is created or updated.
 *
 * Use this hook to modify or enrich the session before it is persisted. The callback receives the resolved session along with optional claims obtained during authentication and any custom application state.
 *
 * Common use cases include:
 * - Adding custom properties to the session
 * - Mapping or filtering claims
 * - Attaching tenant or application-specific metadata
 *
 * @category Types (Handler)
 *
 * @param session The session being created or updated. Changes made to this object are persisted.
 * @param idToken Optional claims extracted from the ID token.
 * @param userInfo Optional claims returned from the `UserInfo` endpoint.
 * @param state Optional application state created during the authentication request.
 * @returns Returns a promise or void. Execution continues once the callback completes.
 */
export type OnSessionCreating = (
  /**
   * The session being created or updated.
   */
  session: MonoCloudSession,

  /**
   * Optional claims extracted from the ID token.
   */
  idToken?: Partial<IdTokenClaims>,

  /**
   * Optional claims returned from the `UserInfo` endpoint.
   */
  userInfo?: UserinfoResponse,

  /**
   * Optional application state associated with the authentication flow.
   */
  state?: ApplicationState
) => Promise<void> | void;

/**
 * Callback invoked when the authentication state is being created before redirecting the user to the authorization server.
 *
 * Use this hook to attach custom application state that should survive the authentication round-trip and be available after the user returns from sign-in.
 *
 * The returned value is stored securely and later provided during session creation.
 *
 * Common use cases include:
 * - Preserving return URLs or navigation context
 * - Passing tenant or organization identifiers
 * - Storing temporary workflow state across authentication
 *
 * @category Types (Handler)
 *
 * @param req The incoming request initiating authentication.
 * @returns Returns an application state object, either synchronously or as a Promise.
 */
export type OnSetApplicationState = (
  /**
   * The incoming request initiating authentication.
   */
  req: MonoCloudRequest
) => Promise<ApplicationState> | ApplicationState;

/**
 * Represents the token set associated with the currently authenticated user.
 *
 * This object extends {@link AccessToken} and includes additional tokens issued during authentication, along with convenience metadata used by the SDK to indicate token validity.
 *
 * @category Types
 */
export interface MonoCloudTokens extends AccessToken {
  /**
   * The ID token issued during authentication. Contains identity claims about the authenticated user.
   */
  idToken?: string;

  /**
   * The refresh token used to obtain new access tokens without requiring the user to re-authenticate.
   */
  refreshToken?: string;

  /**
   * Indicates whether the current access token is expired at the time of evaluation.
   */
  isExpired: boolean;
}

/**
 * Defines a callback invoked when an unexpected error occurs during execution of authentication endpoints such as sign-in, callback, sign-out, or userinfo.
 *
 * This handler allows applications to log, transform, or respond to errors before the SDK applies its default error handling behavior.
 *
 * @category Types (Handler)
 *
 * @param error - The error thrown during endpoint execution.
 */
export type OnError = (error: Error) => Promise<any> | any;

/**
 * Options used to customize the sign-in flow.
 *
 * @category Types
 */
export interface SignInOptions {
  /**
   * Relative URL to redirect the user to after successful authentication.
   *
   * If not provided, the application base URL (`appUrl`) is used.
   */
  returnUrl?: string;

  /**
   * When `true`, initiates the user registration (sign-up) flow instead of a standard sign-in.
   */
  register?: boolean;

  /**
   * Additional authorization parameters merged into the authentication request.
   */
  authParams?: AuthorizationParams;

  /**
   * Callback invoked if an unexpected error occurs during the sign-in flow.
   */
  onError?: OnError;
}

/**
 * Options used to customize callback processing after authentication.
 *
 * @category Types
 */
export interface CallbackOptions {
  /**
   * When `true`, fetches user profile data from the `UserInfo` endpoint after the authorization code exchange completes.
   */
  fetchUserInfo?: boolean;

  /**
   * Redirect URI sent to the token endpoint during the authorization code exchange.
   *
   * > This must match the redirect URI used during the sign-in request.
   */
  redirectUri?: string;

  /**
   * Callback invoked if an unexpected error occurs while processing the authentication callback.
   */
  onError?: OnError;
}

/**
 * Options used to customize the behavior of the userinfo handler.
 *
 * @category Types
 */
export interface UserInfoOptions {
  /**
   * When `true`, forces user profile data to be re-fetched from the authentication service instead of using cached session data.
   */
  refresh?: boolean;

  /**
   * Callback invoked if an unexpected error occurs while retrieving user information.
   */
  onError?: OnError;
}

/**
 * Options used to customize the behavior of the sign-out handler.
 *
 * @category Types
 */
export interface SignOutOptions extends EndSessionParameters {
  /**
   * When `true`, also signs the user out of the MonoCloud session (Single Sign-Out) in addition to the local application session.
   */
  federatedSignOut?: boolean;

  /**
   * Callback invoked if an unexpected error occurs during the sign-out flow.
   */
  onError?: OnError;
}

/**
 * Options used to control token retrieval and refresh behavior when calling `getTokens()`.
 *
 * @category Types
 */
export interface GetTokensOptions extends RefreshGrantOptions {
  /**
   * When `true`, forces a refresh of the access token even if the current token has not expired.
   */
  forceRefresh?: boolean;

  /**
   * When enabled, refetches user information from the `UserInfo` endpoint after tokens are refreshed.
   */
  refetchUserInfo?: boolean;
}

/**
 * Options used to control session retrieval behavior when calling `getSession()`.
 *
 * @category Types
 */
export interface GetSessionOptions {
  /**
   * When enabled, re-fetches user information from the `UserInfo` endpoint and updates the current session.
   */
  refetchUserInfo?: boolean;
}
