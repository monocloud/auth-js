import type {
  AccessToken,
  AuthorizationParams,
  Authenticators,
  AuthState,
  ClientAuthMethod,
  DisplayOptions,
  IdTokenClaims,
  Jwk,
  MonoCloudSession,
  Prompt,
  RefreshGrantOptions,
  ResponseTypes,
  SecurityAlgorithms,
  UserinfoResponse,
} from '@monocloud/auth-core';

/**
 * Defines a storage adapter used to persist session data.
 *
 * Implement this interface to plug a custom storage backend (for example, an
 * encrypted store, secure cookie helper, or a wrapper around `IndexedDB`) into
 * `MonoCloudWebJSClient`.
 *
 * Built-in implementations:
 * - {@link LocalStorage} (default) - backed by `window.localStorage`.
 * - {@link SessionStorage} - backed by `window.sessionStorage`.
 * - {@link MemoryStorage} - in-memory store, useful for testing.
 *
 * @category Types
 */
export interface IStorage {
  /**
   * Retrieves the value associated with the given key.
   *
   * @param key The unique identifier for the stored item.
   * @returns The stored value as a string, or `null` if the key does not exist.
   */
  getItem(key: string): Promise<string | null>;

  /**
   * Removes the item associated with the specified key from storage.
   *
   * @param key The unique identifier of the item to remove.
   */
  removeItem(key: string): Promise<void>;

  /**
   * Stores a key-value pair in the storage.
   *
   * @param key The unique identifier for the item.
   * @param value The string value to store.
   */
  setItem(key: string, value: string): Promise<void>;
}

/**
 * Represents an additional resource indicator that can be requested when acquiring tokens.
 *
 * Resource indicators allow access tokens to be scoped to specific APIs or audiences. Multiple indicators can be configured to request tokens for different protected resources during the same authentication flow.
 *
 * @category Types
 */
export interface Indicator {
  /**
   * Resource (or space-separated list of resources) the access token should be scoped to.
   */
  resource: string;

  /**
   * Optional space-separated list of scopes to request specifically for this resource.
   */
  scopes?: string;
}

/**
 * Subset of {@link AuthorizationParams} that can be pre-configured as defaults for every authentication request.
 *
 * Per-request values (`state`, `nonce`, `codeChallenge`, `codeChallengeMethod`, `redirectUri`) are managed internally by the SDK and cannot be overridden here.
 *
 * @category Types
 */
export type DefaultAuthParams = Pick<
  AuthorizationParams,
  | 'scopes'
  | 'resource'
  | 'responseType'
  | 'prompt'
  | 'display'
  | 'uiLocales'
  | 'acrValues'
  | 'maxAge'
  | 'loginHint'
  | 'authenticatorHint'
  | 'audience'
  | 'idTokenHint'
>;

/**
 * Configuration options used to initialize {@link MonoCloudWebJSClient}.
 *
 * @category Types
 */
export interface MonoCloudWebJSClientOptions {
  /**
   * MonoCloud tenant domain.
   *
   * @example "https://your-tenant.us.monocloud.com"
   */
  tenantDomain: string;

  /**
   * Client identifier of the application registered in MonoCloud.
   */
  clientId: string;

  /**
   * The base URL of the application implementing authentication.
   *
   * Used to construct redirect URLs and validate cross-origin messages received from popups or iframes.
   *
   * If omitted, it defaults to the current page's origin (`window.location.origin`).
   *
   * @example "https://example.com"
   */
  appUrl?: string;

  /**
   * Relative callback path where MonoCloud redirects the user after sign-in.
   *
   * This URL must be registered in the application's callback URL settings in MonoCloud. If omitted, the callback URL defaults to `appUrl` with path `/`.
   *
   * @example "/callback"
   */
  callbackPath?: string;

  /**
   * Determines whether the ID token signature and claims should be validated.
   *
   * Disabling validation is not recommended.
   *
   * @defaultValue true
   */
  validateIdToken?: boolean;

  /**
   * Determines whether user profile data is fetched from the UserInfo endpoint after authentication.
   *
   * @defaultValue true
   */
  fetchUserinfo?: boolean;

  /**
   * When `true`, signs the user out from both the application and MonoCloud (Single Sign-Out).
   *
   * @defaultValue true
   */
  federatedSignOut?: boolean;

  /**
   * List of ID token claims to exclude when constructing the final user object stored on the session.
   *
   * If omitted, a default set of protocol claims are removed.
   */
  filteredIdTokenClaims?: string[];

  /**
   * Timeout (in seconds) for popup and silent (iframe) authentication windows before rejecting with a timeout error.
   *
   * Applies to `signIn`, `signOut`, and `signInSilent`.
   *
   * @defaultValue 600 (seconds)
   */
  authWindowTimeout?: number;

  /**
   * The width of the popup window in pixels.
   *
   * Used to size and center the window when `signIn` or `signOut` is called with `mode: 'popup'`.
   *
   * @defaultValue 375
   */
  popupWindowWidth?: number;

  /**
   * The height of the popup window in pixels.
   *
   * Used to size and center the window when `signIn` or `signOut` is called with `mode: 'popup'`.
   *
   * @defaultValue 600
   */
  popupWindowHeight?: number;

  /**
   * Maximum allowed clock skew (in seconds) for claims validations.
   *
   * @defaultValue 0 (seconds)
   */
  clockSkew?: number;

  /**
   * Maximum allowed clock tolerance (in seconds) applied to time-based claims validations.
   *
   * @defaultValue 60 (seconds)
   */
  clockTolerance?: number;

  /**
   * Relative path where MonoCloud redirects the user after sign-out.
   *
   * This URL must be registered in the application's sign-out URLs in MonoCloud. If omitted, the sign-out callback URL defaults to `appUrl` with path `/`.
   *
   * @example "/signout"
   */
  signOutPath?: string;

  /**
   * Client secret or JSON Web Key used for client authentication.
   *
   * Only required for confidential clients (for example, when using `client_secret_jwt` or `private_key_jwt`).
   */
  clientSecret?: string | Jwk;

  /**
   * Method used for client authentication when calling the token endpoint.
   */
  clientAuthMethod?: ClientAuthMethod;

  /**
   * Expected signing algorithm used to validate ID token signatures.
   *
   * @defaultValue 'RS256'
   */
  idTokenSigningAlgorithm?: SecurityAlgorithms;

  /**
   * A unique identifier that differentiates sessions when multiple clients are used within the same application.
   *
   * This key is appended to the internal session storage key to prevent collisions when multiple `MonoCloudWebJSClient` instances share the same `clientId`.
   */
  sessionKey?: string;

  /**
   * Default authorization parameters to include in authentication requests.
   *
   * Only a subset of {@link AuthorizationParams} is configurable here; per-request values (`state`, `nonce`, `codeChallenge`, `codeChallengeMethod`, `redirectUri`) are managed internally by the SDK.
   *
   * If `scopes` is not set (here or on the `signIn` call), the SDK defaults to `'openid profile email'`.
   *
   * **Hybrid response types** (`code id_token`, `code token`, `code id_token token`) are supported, but the SDK always completes the back-channel authorization code exchange and uses those tokens. The front-channel `id_token` and `access_token` returned in the URL fragment are only checked for presence; they are not validated and are not stored on the session - the authoritative tokens come from the code exchange, where the ID token signature, nonce, and claims are validated.
   */
  defaultAuthParams?: DefaultAuthParams;

  /**
   * Additional resources that can be requested via `getTokens()`.
   */
  resources?: Indicator[];

  /**
   * Duration (in seconds) to cache the JSON Web Key Set (JWKS) document after it is fetched from the authorization server.
   */
  jwksCacheDuration?: number;

  /**
   * Duration (in seconds) to cache OpenID Connect discovery metadata after it is fetched from the authorization server.
   */
  metadataCacheDuration?: number;

  /**
   * Storage implementation used to persist sessions. Defaults to {@link LocalStorage}.
   */
  storage?: IStorage;

  /**
   * Callback executed after a successful sign-in or sign-out callback. Useful for client-side router integration.
   */
  postCallback?: PostCallback;

  /**
   * Hook invoked while creating or updating session.
   */
  onSessionCreating?: OnSessionCreating;
}

/**
 * Custom application state passed through an authentication flow.
 *
 * Captured when the flow is initiated (for example via `signIn` or `signInSilent`) and surfaced to the {@link OnSessionCreating} hook when the session is constructed.
 *
 * @category Types
 */
export type ApplicationState = Record<string, unknown>;

/**
 * Callback invoked when a session is being created or updated.
 *
 * Use this hook to modify or enrich the session before it is persisted - for example, to attach custom claims, normalize user data, or apply application-specific logic.
 *
 * @category Types (Handler)
 *
 * @param session The session being created or updated. Changes made to this object are persisted.
 * @param idToken Optional claims extracted from the ID token received during authentication.
 * @param userInfo Optional claims returned from the UserInfo endpoint.
 * @param state Optional application state associated with the authentication request.
 * @returns Returns a promise or void. Execution continues once the callback completes.
 */
export type OnSessionCreating = (
  /**
   * The session being created or updated.
   */
  session: MonoCloudSession,

  /**
   * Optional claims extracted from the ID token received during authentication.
   */
  idToken?: Partial<IdTokenClaims>,

  /**
   * Optional claims returned from the UserInfo endpoint.
   */
  userInfo?: UserinfoResponse,

  /**
   * Optional application state associated with the authentication request.
   */
  state?: ApplicationState
) => Promise<void> | void;

/**
 * Interaction modes supported for sign-in and sign-out flows.
 *
 * @category Types (Enums)
 */
export type InteractionMode =
  /**
   * Opens a popup window for interactive authentication and keeps the user on the current page.
   */
  | 'popup'

  /**
   * Performs a full-page redirect to the authorization server.
   */
  | 'redirect';

/**
 * Callback executed after sign-in or sign-out callback processing.
 *
 * The default implementation removes query parameters from the current URL on `signIn` (no navigation) or performs a full page reload to `returnUrl`. Provide a custom implementation to integrate with a client-side router and avoid full page reloads.
 *
 * @category Types (Handler)
 *
 * @param state Callback state.
 * @returns Returns a promise or void. Execution continues once the callback completes.
 */
export type PostCallback = (state: CallbackState) => Promise<void> | void;

/**
 * Options used to customize the sign-in flow.
 *
 * @category Types
 */
export interface SignInOptions {
  /**
   * Specifies the preferred authenticator or identity provider to use for sign-in.
   */
  authenticatorHint?: Authenticators;

  /**
   * Maximum allowed time (in seconds) since the user's last authentication.
   *
   * Used to force re-authentication if the time since the last sign-in exceeds this value.
   */
  maxAge?: number;

  /**
   * Hint identifying the user (for example, an email or username). Used to pre-fill or optimize the sign-in experience.
   *
   * @example "user@example.com"
   */
  loginHint?: string;

  /**
   * Preferred locale(s) for the sign-in UI.
   *
   * @example "en-US"
   */
  uiLocales?: string;

  /**
   * When `true`, starts the sign-up (user registration) flow instead of a standard sign-in.
   *
   * Equivalent to setting `prompt: 'create'`. If both are provided, `signUp: true` wins.
   */
  signUp?: boolean;

  /**
   * Specifies the desired authentication interaction behavior.
   */
  prompt?: Prompt;

  /**
   * Authentication Context Class Reference (ACR) values requesting specific authentication assurance levels or methods.
   */
  acrValues?: string[];

  /**
   * Preferred display mode for the authentication UI.
   */
  display?: DisplayOptions;

  /**
   * Determines the interaction mode for the sign-in flow.
   *
   * @defaultValue 'redirect'
   */
  mode?: InteractionMode;

  /**
   * Relative URL to navigate to after sign-in completes.
   */
  returnUrl?: string;

  /**
   * Space-separated scopes requested from the authorization server for this specific sign-in.
   *
   * Merged with `defaultAuthParams.scopes` and any indicator scopes configured on the client.
   */
  scopes?: string;

  /**
   * Space-separated resources the access token should be scoped to for this specific sign-in.
   *
   * Merged with `defaultAuthParams.resource` and any indicator resources configured on the client.
   */
  resource?: string;

  /**
   * Identifies the target API (audience) that the issued access token is intended for.
   */
  audience?: string;

  /**
   * A previously issued ID token sent as the `id_token_hint`. Commonly used alongside `prompt: 'none'` for silent re-authentication.
   */
  idTokenHint?: string;

  /**
   * Custom application state preserved across the authentication round-trip.
   *
   * The value is provided to the {@link OnSessionCreating} hook when the session is constructed.
   */
  appState?: ApplicationState;
}

/**
 * Options used to customize the sign-out flow.
 *
 * @category Types
 */
export interface SignOutOptions {
  /**
   * A previously issued ID token to send as the `id_token_hint` on the logout request.
   *
   * When provided, this overrides the ID token from the current session. Use it to supply the hint manually.
   */
  idTokenHint?: string;

  /**
   * URL to redirect the user to after sign-out completes.
   *
   * This URI must be registered in the application's sign-out URLs in MonoCloud.
   */
  postLogoutRedirectUri?: string;

  /**
   * Determines the interaction mode for the sign-out flow.
   *
   * @defaultValue 'redirect'
   */
  mode?: InteractionMode;

  /**
   * When `true`, signs the user out from both the application and MonoCloud (Single Sign-Out).
   *
   * Overrides the client-level `federatedSignOut` configuration for this specific call. If omitted, the client-level setting is used.
   */
  federatedSignOut?: boolean;

  /**
   * Relative URL to navigate to after sign-out completes.
   */
  returnUrl?: string;
}

/**
 * Options used to customize the session refresh flow.
 *
 * @category Types
 */
export interface RefreshOptions {
  /**
   * Configuration applied to the Refresh Token Grant request, such as overriding the requested scopes or resources.
   */
  refreshGrantOptions?: RefreshGrantOptions;
}

/**
 * Options used to customize the silent sign-in flow.
 *
 * @category Types
 */
export interface SignInSilentOptions {
  /**
   * Maximum allowed time (in seconds) since the user's last authentication.
   *
   * If the existing session is older than this value, the authorization server cannot satisfy the silent request and will reject with `login_required`.
   */
  maxAge?: number;

  /**
   * Hint identifying the user (for example, an email or username). Helps the authorization server disambiguate when multiple sessions are present.
   *
   * @example "user@example.com"
   */
  loginHint?: string;

  /**
   * Authentication Context Class Reference (ACR) values requesting specific authentication assurance levels or methods.
   *
   * If the existing session does not satisfy the requested ACR, the authorization server will reject with `interaction_required`.
   */
  acrValues?: string[];

  /**
   * Space-separated scopes requested from the authorization server for this specific silent sign-in.
   *
   * Merged with `defaultAuthParams.scopes` and any indicator scopes configured on the client.
   */
  scopes?: string;

  /**
   * Space-separated resources the access token should be scoped to for this specific silent sign-in.
   *
   * Merged with `defaultAuthParams.resource` and any indicator resources configured on the client.
   */
  resource?: string;

  /**
   * Custom application state preserved across the silent authentication round-trip.
   *
   * The value is provided to the {@link OnSessionCreating} hook when the session is constructed.
   */
  appState?: ApplicationState;
}

/**
 * Internal state persisted between an authorization request and its callback.
 *
 * @category Types
 */
export interface CallbackState extends Partial<AuthState> {
  /**
   * Indicates whether the callback represents a sign-out flow.
   */
  signOut?: boolean;

  /**
   * Interaction mode used to initiate the original authorization request.
   */
  mode: 'popup' | 'redirect' | 'silent';

  /**
   * URL to navigate to after the callback has been processed.
   */
  returnUrl?: string;

  /**
   * Custom application state associated with the request.
   */
  appState?: ApplicationState;

  /**
   * Response type requested during authorization.
   */
  responseType?: ResponseTypes;
}

/**
 * Message payload posted by popup or iframe callback windows back to the application.
 *
 * @category Types
 */
export interface PostMessageResult {
  /**
   * Source identifier for the post message. Used to distinguish SDK messages from other postMessage senders.
   */
  source: 'monocloud-auth-web-js';

  /**
   * Full callback URL captured by the popup or iframe.
   */
  url: string;
}

/**
 * Options used to control token retrieval and refresh behavior in `getTokens()`.
 *
 * @category Types
 */
export interface GetTokensOptions extends RefreshGrantOptions {
  /**
   * When `true`, forces an access token refresh even if the current token has not expired.
   */
  forceRefresh?: boolean;

  /**
   * When enabled, refetches user information from the UserInfo endpoint after tokens are refreshed.
   */
  refetchUserInfo?: boolean;
}

/**
 * Tokens available in the current session.
 *
 * Extends {@link AccessToken} with the ID token, refresh token, and a convenience flag indicating whether the access token has expired.
 *
 * @category Types
 */
export interface MonoCloudTokens extends AccessToken {
  /**
   * ID token issued during authentication.
   */
  idToken?: string;

  /**
   * Refresh token issued during authentication, if any.
   */
  refreshToken?: string;

  /**
   * Indicates whether the access token is expired at the time of evaluation.
   */
  isExpired: boolean;
}
