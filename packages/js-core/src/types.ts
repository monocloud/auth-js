import type {
  Authenticators,
  AuthState,
  DisplayOptions,
  Jwk,
  SecurityAlgorithms,
  MonoCloudSession,
  Prompt,
  RefreshGrantOptions,
  ResponseTypes,
  ClientAuthMethod,
  AuthorizationParams,
  IdTokenClaims,
  UserinfoResponse,
  AccessToken,
} from '@monocloud/auth-core';

/**
 * Storage interface for storing session data.
 *
 * @category Types
 */
export interface IStorage {
  /**
   * Retrieves the value associated with the given key.
   *
   * @param key - The unique identifier for the stored item
   * @returns The stored value as a string, or `null` if the key does not exist
   */
  getItem(key: string): Promise<string | null>;

  /**
   * Removes the item associated with the specified key from storage.
   *
   * @param key - The unique identifier of the item to be removed
   */
  removeItem(key: string): Promise<void>;

  /**
   * Stores a key-value pair in the storage.
   *
   * @param key - The unique identifier for the item
   * @param value - The string value to be stored
   */
  setItem(key: string, value: string): Promise<void>;
}

/**
 * Represents an indicator for additional resources that can be requested.
 *
 * @category Types
 */
export interface Indicator {
  /**
   * Space separated list of resources to scope the access token to
   */
  resource: string;
  /**
   * Optional: Space separated list of scopes to request
   */
  scopes?: string;
}

/**
 * Configuration options for initializing a MonoCloudJSCoreClient.
 *
 * @category Types
 */
export interface MonoCloudJSCoreClientOptions {
  /**
   * Tenant domain.
   *
   * @example "https://your-domain.as.monocloud.com"
   */
  tenantDomain: string;

  /**
   * ID of the client.
   */
  clientId: string;

  /**
   * The base URL of the application implementing authentication.
   *
   * @example "https://example.com"
   */
  appUrl: string;

  /**
   * The relative path where MonoCloud redirects the user after sign in.
   * This url should be registered in the client's callback urls settings. If callback path is not set
   * the callback url is set to `appUrl` with path `/`.
   *
   * @example "/callback"
   */
  callbackPath?: string;

  /**
   * Whether the ID token should be validated.
   *
   * @defaultValue true
   */
  validateIdToken?: boolean;

  /**
   * Determines whether to fetch from userinfo after authentication.
   *
   * @defaultValue true
   */
  fetchUserinfo?: boolean;

  /**
   * When set to `true`, signs user out from the app and MonoCloud globally.
   *
   * @defaultValue true
   */
  federatedSignOut?: boolean;

  /**
   * Array of strings representing the filtered ID token claims.
   */
  filteredIdTokenClaims?: string[];

  /**
   * Timeout duration (in seconds) for popups and iframes.
   *
   * @defaultValue 600
   */
  authWindowTimeout?: number;

  /**
   * The width of the popup window in pixels.
   *
   * This value is used to size and center the window when `signIn` or `signOut`
   * is called with `mode: 'popup'`.
   *
   * @defaultValue 375
   */
  popupWindowWidth?: number;

  /**
   * The height of the popup window in pixels.
   *
   * This value is used to size and center the window when `signIn` or `signOut`
   * is called with `mode: 'popup'`.
   *
   * @defaultValue 600
   */
  popupWindowHeight?: number;

  /**
   * The maximum allowed clock skew (in seconds) for token validation.
   *
   * @defaultValue 60
   */
  clockSkew?: number;

  /**
   * The maximum allowed clock tolerance (in seconds) for date time based claims.
   *
   * @defaultValue 60
   */
  clockTolerance?: number;

  /**
   * Specifies the OpenId response type for the authentication flow.
   *
   * @defaultValue "code"
   */
  responseType?: ResponseTypes;

  /**
   * Path where MonoCloud redirects after the user signs out.
   *
   * @example "/signout"
   */
  signOutCallbackPath?: string | null;

  /**
   * Client secret or JSON Web Key for client authentication.
   */
  clientSecret?: string | Jwk;

  /**
   * Method used for client authentication.
   */
  clientAuthMethod?: ClientAuthMethod;

  /**
   * Algorithm used for verifying ID token signature.
   *
   * @defaultValue "RS256"
   */
  idTokenSigningAlgorithm?: SecurityAlgorithms;

  /**
   * A unique identifier that differentiates sessions when multiple clients are used within the same application.
   * This key is concatenated with internal session key to prevent conflicts.
   */
  sessionKey?: string;

  /**
   * Default authorization parameters to include in authentication requests.
   *
   * @defaultValue { scope: 'openid', response_type: 'code' }
   */
  defaultAuthParams?: AuthorizationParams;

  /**
   * Additional resources that can be requested via `getTokens()`.
   */
  resources?: Indicator[];

  /**
   * The duration in seconds to cache the JWKS document after it is fetched.
   *
   * @defaultValue 60
   */
  jwksCacheDuration?: number;

  /**
   * Time in seconds to cache the metadata document after it is fetched.
   *
   * @defaultValue 60
   */
  metadataCacheDuration?: number;
}

/**
 * The custom application state used for preserving context during redirection.
 *
 * @category Types
 */
export type ApplicationState = Record<string, any>;

/**
 * Defines a callback function to be executed when a new session is being created or updated.
 *
 * This function receives parameters related to the session being created,
 * including the session object itself, optional ID token and user information claims,
 * and the application state.
 *
 * @category Types (Handler)
 *
 * @param session - The Session object being created.
 * @param idToken - Optional. Claims from the ID token received during authentication.
 * @param userInfo - Optional. Claims from the user information received during authentication.
 * @param state - Optional. The application state associated with the session.
 * @returns A Promise that resolves when the operation is completed, or void.
 */
export type OnSessionCreating = (
  session: MonoCloudSession,
  idToken?: Partial<IdTokenClaims>,
  userInfo?: UserinfoResponse,
  state?: ApplicationState
) => Promise<void> | void;

/**
 * Defines the interaction modes supported by the client for sign in and sign out.
 *
 * @category Types
 */
export type InteractionMode = 'popup' | 'redirect';

/**
 * Parameters for the post callback function after handling a redirect or popup flow.
 *
 * @category Types
 */
export type PostCallbackParams =
  | {
      type: 'signIn';
      mode: InteractionMode | 'silent';
      returnUrl?: string;
    }
  | { type: 'signOut'; mode: InteractionMode; returnUrl?: string };

/**
 * A function that is executed after a sign in or sign out callback.
 *
 * Use this function to navigate to another route or execute business logic instead of triggering a full page reload.
 *
 * @category Types (Handler)
 */
export type PostCallback = (state: PostCallbackParams) => Promise<void> | void;

/**
 * Options for configuring the `signIn()` method.
 *
 * @category Types
 */
export interface SignInOptions {
  /**
   * Specifies the preferred authenticator for sign in.
   */
  authenticatorHint?: Authenticators;

  /**
   * Maximum allowed time (in seconds) since the user's last authentication.
   * Used to force re-authentication if the last login exceeds this time.
   */
  maxAge?: number;

  /**
   * Provides a hint about the user's login identifier. Used to pre-fill or suggest a username.
   *
   * @example "user@example.com"
   */
  loginHint?: string;

  /**
   * Specifies preferred locales for the login pages.
   *
   * @example "en-US"
   */
  uiLocales?: string;

  /**
   * Redirects to the sign up page if set to `true`.
   */
  signUp?: boolean;

  /**
   * The desired authentication behaviour.
   */
  prompt?: Prompt;

  /**
   * An array of authentication context class references (ACRs).
   */
  acrValues?: string[];

  /**
   * The desired user interface mode.
   */
  display?: DisplayOptions;

  /**
   * Determines the interaction mode for the sign in.
   *
   * @defaultValue "redirect"
   */
  mode?: InteractionMode;

  /**
   * The relative path to return to after sign in.
   */
  returnUrl?: string;

  /**
   * Space-separated scopes requested from the authorization server.
   */
  scopes?: string;

  /**
   * Space-separated resources the access token should be scoped to.
   */
  resource?: string;

  /**
   * Additional custom application specific state information.
   */
  appState?: ApplicationState;
}

/**
 * Options for configuring the `signOut()` method.
 *
 * @category Types
 */
export interface SignOutOptions {
  /**
   * Specifies the URI to redirect to after successful sign out. The URI should be saved in the client's
   * sign out uri section.
   */
  postLogoutRedirectUri?: string;

  /**
   * Determines the interaction mode for the sign-out process.
   *
   * @defaultValue "redirect"
   */
  mode?: InteractionMode;

  /**
   * The relative path to return to after sign out.
   */
  returnUrl?: string;
}

/**
 * Defines the modes of interaction for refreshing session.
 *
 * @category Types
 */
export type RefreshMode = 'popup' | 'refresh_token' | 'silent';

/**
 * Options for configuring the `refreshSession()` method.
 *
 * @category Types
 */
export interface RefreshOptions {
  /**
   * Determines the interaction mode for the session refresh process.
   *
   * > **WARNING**: Using `popup` or `silent` will overwrite the current session since it initiates a fresh authorization request.
   *
   * @defaultValue "silent"
   */
  mode?: RefreshMode;

  /**
   * Configuration specifically for the Refresh Token Grant flow.
   */
  refreshGrantOptions?: RefreshGrantOptions;

  /**
   * Additional custom application specific state information.
   */
  appState?: ApplicationState;
}

/**
 * Internal interface used for storing the authentication request state.
 *
 * @category Types
 */
export interface CallbackState extends Partial<AuthState> {
  signOut?: boolean;
  mode: 'popup' | 'redirect' | 'silent';
  returnUrl?: string;
  appState?: ApplicationState;
}

/**
 * Result structure emitted by the popup or iframe after successfully authenticating.
 *
 * @category Types
 */
export interface PostMessageResult {
  source: 'monocloud-auth-js-core';
  url: string;
}

/**
 * Represents options for the `getTokens()` handler.
 *
 * @category Types
 */
export interface GetTokensOptions extends RefreshGrantOptions {
  /**
   * Specifies whether to force the refresh of the access token, bypassing expiration checks.
   */
  forceRefresh?: boolean;

  /**
   * Determines whether to refetch the user information from the OpenID Provider.
   */
  refetchUserInfo?: boolean;
}

/**
 * Represents the tokens obtained during authentication that are available in the session.
 *
 * @category Types
 */
export interface MonoCloudTokens extends AccessToken {
  /**
   * The ID token obtained during authentication.
   */
  idToken?: string;

  /**
   * The refresh token obtained during authentication.
   */
  refreshToken?: string;

  /**
   * Specifies if the access token has expired.
   */
  isExpired: boolean;
}
