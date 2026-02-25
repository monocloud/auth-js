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
 * Defines a storage adapter used to persist session data.
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
 * @category Types
 */
export interface Indicator {
  /**
   * Space-separated list of resources to scope the access token to.
   */
  resource: string;

  /**
   * Optional space-separated list of scopes to request.
   */
  scopes?: string;
}

/**
 * Configuration options for initializing `MonoCloudJSCoreClient`.
 *
 * @category Types
 */
export interface MonoCloudJSCoreClientOptions {
  /**
   * MonoCloud tenant domain.
   *
   * @example "https://your-domain.as.monocloud.com"
   */
  tenantDomain: string;

  /**
   * Client identifier of the application registered in MonoCloud.
   */
  clientId: string;

  /**
   * The base URL of the application implementing authentication.
   *
   * @example "https://example.com"
   */
  appUrl: string;

  /**
   * Relative callback path where MonoCloud redirects the user after sign-in.
   *
   * This URL must be registered in the application's callback URL settings.
   * If omitted, the callback URL defaults to `appUrl` with path `/`.
   *
   * @example /callback
   */
  callbackPath?: string;

  /**
   * Whether the ID token should be validated.
   *
   * @defaultValue true
   */
  validateIdToken?: boolean;

  /**
   * Determines whether to fetch UserInfo after authentication.
   *
   * @defaultValue true
   */
  fetchUserinfo?: boolean;

  /**
   * When `true`, signs the user out from both the app and MonoCloud.
   *
   * @defaultValue true
   */
  federatedSignOut?: boolean;

  /** List of ID token claims to exclude when constructing the final user object. */
  filteredIdTokenClaims?: string[];

  /**
   * Timeout duration (in seconds) for popups and iframes.
   *
   * @defaultValue 600 (seconds)
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
   * @defaultValue 60 (seconds)
   */
  clockSkew?: number;

  /**
   * The maximum allowed clock tolerance for date-time-based claims.
   *
   * @defaultValue 60 (seconds)
   */
  clockTolerance?: number;

  /**
   * Specifies the OpenID Connect response type for the authentication flow.
   *
   * @defaultValue 'code'
   */
  responseType?: ResponseTypes;

  /**
   * Relative path where MonoCloud redirects the user after sign-out.
   *
   * @example /signout
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
   * @defaultValue 'RS256'
   */
  idTokenSigningAlgorithm?: SecurityAlgorithms;

  /**
   * A unique identifier that differentiates sessions when multiple clients are used within the same application.
   *
   * This key is appended to the internal session key to prevent conflicts.
   */
  sessionKey?: string;

  /**
   * Default authorization parameters to include in authentication requests.
   */
  defaultAuthParams?: AuthorizationParams;

  /**
   * Additional resources that can be requested in `getTokens()`.
   */
  resources?: Indicator[];

  /**
   * The duration in seconds to cache the JWKS document after it is fetched.
   *
   * @defaultValue 300 (seconds)
   */
  jwksCacheDuration?: number;

  /**
   * Time in seconds to cache the metadata document after it is fetched.
   *
   * @defaultValue 300 (seconds)
   */
  metadataCacheDuration?: number;
}

/**
 * Custom application state passed through authentication flows.
 *
 * @category Types
 */
export type ApplicationState = Record<string, any>;

/**
 * Callback invoked when a session is being created or updated.
 *
 * @category Types (Handler)
 *
 * @param session The session object being created.
 * @param idToken Optional claims from the ID token received during authentication.
 * @param userInfo Optional claims from the UserInfo response.
 * @param state Optional application state associated with the session.
 * @returns Returns `void` or a `Promise<void>`.
 */
export type OnSessionCreating = (
  session: MonoCloudSession,
  idToken?: Partial<IdTokenClaims>,
  userInfo?: UserinfoResponse,
  state?: ApplicationState
) => Promise<void> | void;

/**
 * Interaction modes supported for sign-in and sign-out flows.
 *
 * @category Types (Enums)
 */
export type InteractionMode = 'popup' | 'redirect';

/**
 * Metadata passed to `PostCallback` after callback processing.
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
 * Callback executed after sign-in or sign-out callback processing.
 *
 * @category Types (Handler)
 *
 * @param state Metadata describing the completed flow.
 * @returns Returns `void` or a `Promise<void>`.
 */
export type PostCallback = (state: PostCallbackParams) => Promise<void> | void;

/**
 * Options for `signIn()`.
 *
 * @category Types
 */
export interface SignInOptions {
  /**
   * Specifies the preferred authenticator for sign-in.
   */
  authenticatorHint?: Authenticators;

  /**
   * Maximum allowed time (in seconds) since the user's last authentication.
   *
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
   * Specifies preferred locales for the sign-in page.
   *
   * @example "en-US"
   */
  uiLocales?: string;

  /**
   * When `true`, starts the sign-up flow.
   */
  signUp?: boolean;

  /**
   * The desired authentication behavior.
   */
  prompt?: Prompt;

  /** An array of authentication context class references (ACRs). */
  acrValues?: string[];

  /** The desired user interface mode. */
  display?: DisplayOptions;

  /**
   * Determines the interaction mode for sign-in.
   *
   * @defaultValue 'redirect'
   */
  mode?: InteractionMode;

  /**
   * Relative path to return to after sign-in.
   */
  returnUrl?: string;

  /** Space-separated scopes requested from the authorization server. */
  scopes?: string;

  /** Space-separated resources the access token should be scoped to. */
  resource?: string;

  /** Additional custom application-specific state information. */
  appState?: ApplicationState;
}

/**
 * Options for `signOut()`.
 *
 * @category Types
 */
export interface SignOutOptions {
  /**
   * URI to redirect to after successful sign-out.
   *
   * This URI must be configured in the application's allowed sign-out callback URLs.
   */
  postLogoutRedirectUri?: string;

  /**
   * Determines the interaction mode for the sign-out process.
   *
   * @defaultValue 'redirect'
   */
  mode?: InteractionMode;

  /**
   * Relative path to return to after sign-out.
   */
  returnUrl?: string;
}

/**
 * Interaction modes supported by `refreshSession()`.
 *
 * @category Types (Enums)
 */
export type RefreshMode = 'popup' | 'refresh_token' | 'silent';

/**
 * Options for `refreshSession()`.
 *
 * @category Types
 */
export interface RefreshOptions {
  /**
   * Determines the interaction mode for the session refresh process.
   *
   * Using `popup` or `silent` starts a new authorization request and replaces the current session.
   *
   * @defaultValue 'silent'
   */
  mode?: RefreshMode;

  /** Configuration specific to the Refresh Token Grant flow. */
  refreshGrantOptions?: RefreshGrantOptions;

  /** Additional custom application-specific state information. */
  appState?: ApplicationState;
}

/**
 * Internal state persisted between authorization start and callback processing.
 *
 * @category Types
 */
export interface CallbackState extends Partial<AuthState> {
  signOut?: boolean;
  mode: 'popup' | 'redirect' | 'silent';
  returnUrl?: string;
  appState?: ApplicationState;
  responseType?: ResponseTypes;
}

/**
 * Message payload posted by popup or iframe callback windows.
 *
 * @category Types
 */
export interface PostMessageResult {
  source: 'monocloud-auth-js-core';
  url: string;
}

/**
 * Options for `getTokens()`.
 *
 * @category Types
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
 * Tokens available in the current session.
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
