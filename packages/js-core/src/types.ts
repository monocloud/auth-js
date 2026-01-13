import type {
  Authenticators,
  AuthState,
  DisplayOptions,
  Jwk,
  JWSAlgorithm,
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
 */
export interface IStorage {
  /**
   * Retrieves the value associated with the given key.
   *
   * @param key - The unique identifier for the stored item
   * @returns The stored value as a string, or null if the key does not exist
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
 * Configuration options for initializing a MonoCloudJsClient.
 */
export interface MonoCloudJSCoreClientOptions {
  /**
   * Tenant domain
   *
   * @example "https://your-domain.as.monocloud.com"
   */
  tenantDomain: string;

  /**
   * Id of the client
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
   * the callback url is set to `appUrl`.
   *
   * @example /callback
   */
  callbackPath?: string;

  /**
   * Whether ID token should be validated.
   *
   * @default true
   */
  validateIdToken?: boolean;

  /**
   * Determines whether to fetch from userinfo after authentication.
   *
   * @default true
   */
  fetchUserinfo?: boolean;

  /**
   * When set to true, signs user out from the app and MonoCloud.
   *
   * @default true
   */
  federatedSignOut?: boolean;

  /**
   *  Array of strings representing the filtered ID token claims.
   */
  filteredIdTokenClaims?: string[];

  /**
   * Timeout duration (in seconds) for popups and iframes.
   *
   * @default 600 (seconds)
   */
  authWindowTimeout?: number;

  /**
   * The width of the popup window in pixels.
   *
   * This value is used to size and center the window when `signIn` or `signOut`
   * is called with `mode: 'popup'`.
   *
   * @default 375
   */
  popupWindowWidth?: number;

  /**
   * The height of the popup window in pixels.
   *
   * This value is used to size and center the window when `signIn` or `signOut`
   * is called with `mode: 'popup'`.
   *
   * @default 600
   */
  popupWindowHeight?: number;

  /**
   * The maximum allowed clock skew (in seconds) for token validation.
   *
   * @default 60 (seconds)
   */
  clockSkew?: number;

  /**
   * The maximum allowed clock tolerance for date time based claims.
   *
   * @default 60 (seconds)
   */
  clockTolerance?: number;

  /**
   * Specifies the OpenId response type for the authentication flow.
   *
   * @default code
   */
  responseType?: ResponseTypes;

  /**
   * Path where MonoCloud redirects after user signs out.
   *
   * @example /signout
   */
  signOutCallbackPath?: string;

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
   * @default RS256
   */
  idTokenSigningAlgorithm?: JWSAlgorithm;

  /**
   * A unique identifier that differentiates sessions when multiple clients are used within the same application.
   * This key is concatenated with internal session key to prevent conflicts.
   */
  sessionKey?: string;

  /**
   * Default authorization parameters to include in authentication requests.
   *
   * @defaultValue {
   *   scope: 'openid',
   *   response_type: 'code'
   * }
   */
  defaultAuthParams?: AuthorizationParams;

  /**
   * Additional resources that can be requested in `getTokens()`.
   *
   */
  resources?: Indicator[];

  /**
   *
   * The duration in seconds to cache the JWKS document after it is fetched.
   *
   * @default 60 (seconds)
   *
   * */
  jwksCacheDuration?: number;

  /**
   *
   * Time in seconds to cache the metadata document after it is fetched.
   *
   * @default 60 (seconds)
   * */
  metadataCacheDuration?: number;
}

/**
 * The custom application state.
 */
export type ApplicationState = Record<string, any>;

/**
 * Defines a callback function to be executed when a new session is being created or updated.
 * This function receives parameters related to the session being created,
 * including the session object itself, optional ID token and user information claims,
 * and the application state.
 *
 * @param session - The Session object being created.
 * @param idToken - Optional. Claims from the ID token received during authentication.
 * @param userInfo - Optional. Claims from the user information received during authentication.
 * @param state - Optional. The application state associated with the session.
 * @returns A Promise that resolves when the operation is completed, or void.
 */
export type OnSessionCreating = (
  /**
   * The Session object being created.
   */
  session: MonoCloudSession,

  /**
   * Optional. Claims from the ID token received during authentication.
   */
  idToken?: Partial<IdTokenClaims>,

  /**
   * Optional. Claims from the user information received during authentication.
   */
  userInfo?: UserinfoResponse,

  /**
   * Optional. The application state associated with the session.
   */
  state?: ApplicationState
) => Promise<void> | void;

/**
 * Defines the interaction modes supported by the client for sign in and sign out.
 */
export type InteractionMode = 'popup' | 'redirect';

/**
 * Parameters for the post callback function
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
 * Use this function to navigate to another route or execute some business logic.
 */
export type PostCallback = (state: PostCallbackParams) => Promise<void> | void;

/**
 * Options for `signIn()` method.
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
   * Specifies preferred locales for the login pages
   *
   * @example en-US
   */
  uiLocales?: string;

  /**
   * Redirects to sign up page if set to true.
   */
  signUp?: boolean;

  /**
   * The desired authentication behaviour.
   */
  prompt?: Prompt;

  /** An array of authentication context class references (ACRs). */
  acrValues?: string[];

  /** The desired user interface mode */
  display?: DisplayOptions;

  /**
   * Determines the interaction mode for the sign in
   *
   * @default redirect
   */
  mode?: InteractionMode;

  /**
   * The relative path to return to after sign in
   */
  returnUrl?: string;

  /** Space-separated scopes requested from the authorization server */
  scopes?: string;

  /** Space-separated resources the access token should be scoped to */
  resource?: string;

  /** Additional custom application specific state information. */
  appState?: ApplicationState;
}

/**
 * Options for `signOut()` method.
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
   * @default redirect
   */
  mode?: InteractionMode;

  /**
   * The relative path to return to after sign out
   */
  returnUrl?: string;
}

/**
 * Defines the modes of interaction for refreshing session.
 */
export type RefreshMode = 'popup' | 'refresh_token' | 'silent';

/**
 * Options for `refreshSession()` method
 */
export interface RefreshOptions {
  /**
   * Determines the interaction mode for the session refresh process.
   *
   * **WARNING ⚠️: Using `popup` or `silent` will overwrite the current sesssion since its a fresh authorization request.**
   *
   * @default redirect
   */
  mode?: RefreshMode;

  /** Configuration specifically for the Refresh Token Grant flow */
  refreshGrantOptions?: RefreshGrantOptions;

  /** Additional custom application specific state information. */
  appState?: ApplicationState;
}

export interface IMonoCloudJSCoreClient {
  /**
   * Process the authentication callback
   */
  processCallback(): Promise<void>;

  /**
   * Initiate the sign-in process
   * @param {SignInOptions} signInOptions Sign-in configuration
   */
  signIn(signInOptions?: SignInOptions): Promise<void>;

  /**
   * Sign out the current user
   * @param {SignOutOptions} signOutOptions Sign-out configuration
   */
  signOut(signOutOptions?: SignOutOptions): Promise<void>;

  /**
   * Refresh the current session
   * @param {RefreshOptions} refreshOptions - Refresh session configuration
   */
  refreshSession(refreshOptions?: RefreshOptions): Promise<void>;

  /**
   * Refetch the user information
   */
  refetchUserInfo(): Promise<void>;

  /**
   * Returns the session of the currently signed in user.
   */
  getSession(): Promise<MonoCloudSession | undefined>;
}

/**
 * Internal interface used for storing the authentication request state.
 */
export interface CallbackState extends Partial<AuthState> {
  signOut?: boolean;
  mode: 'popup' | 'redirect' | 'silent';
  returnUrl?: string;
  appState?: ApplicationState;
}

export interface PostMessageResult {
  source: 'monocloud-auth-js-core';
  url: string;
}

/**
 * Represents options for the GetTokens handler.
 */
export interface GetTokensOptions extends RefreshGrantOptions {
  /**
   * Specifies whether to force the refresh of the access token.
   */
  forceRefresh?: boolean;

  /**
   * Determines whether to refetch the user information.
   */
  refetchUserInfo?: boolean;
}

/**
 * Represents the tokens obtained during authentication that are available in the session.
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
