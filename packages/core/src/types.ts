/** Supported Response Types */
export type ResponseTypes =
  | 'code'
  | 'token'
  | 'id_token'
  | 'id_token token'
  | 'code id_token'
  | 'code token'
  | 'code id_token token';

/** Supported PKCE code challenge methods */
export type CodeChallengeMethod = 'plain' | 'S256';

/** Display options */
export type DisplayOptions = 'page' | 'popup' | 'touch' | 'wap';

/** Allowed Response Modes */
export type ResponseModes = 'form_post' | 'query' | 'fragment';

/** Valid prompt parameter values */
export type Prompt = 'none' | 'login' | 'consent' | 'select_account' | 'create';

/** Parameters for creating Authorization URL */
export interface AuthorizationParams {
  /** A random string used to prevent CSRF attacks */
  state?: string;
  /** Space-separated list of scopes requested from the authorization server */
  scopes?: string;
  /** The URI to redirect the user to after successful sign in */
  redirectUri?: string;
  /**
   * The desired response type from the authorization server.
   * - `code`: Authorization code flow.
   * - `token`: Implicit flow.
   * - `id_token`: Implicit flow with ID token.
   * - `id_token token`: Implicit flow with ID token and access token.
   * - `code id_token`: Authorization code flow with ID token.
   * - `code token`: Authorization code flow with access token.
   * - `code id_token token`: Authorization code flow with ID token and access token.
   */
  responseType?: ResponseTypes;
  /** A cryptographic hash used for proof key for code exchange (PKCE). */
  codeChallenge?: string;
  /**
   * The method used to generate the code challenge, either `plain` or `S256`.
   */
  codeChallengeMethod?: CodeChallengeMethod;
  /** A hint to the authorization server about the desired authenticator the client wishes to authenticate the user with */
  authenticatorHint?: Authenticators;
  /** Maximum allowed time in seconds since the last End-User authentication. */
  maxAge?: number;
  /** A hint to the authorization server about the user's identifier */
  loginHint?: string;
  /** A signed JWT containing the authorization request parameters  */
  request?: string;
  /**
   * The response mode for the authorization response.
   * - `form_post`: Form-encoded POST request.
   * - `query`: URI query parameters.
   * - `fragment`: URI fragment.
   */
  responseMode?: ResponseModes;
  /** An array of authentication context class references (ACRs). */
  acrValues?: string[];
  /** A random string used to associate to the ID token to prevent replay attacks */
  nonce?: string;
  /** User's preferred languages and scripts for the user interface */
  uiLocales?: string;
  /** The desired user interface mode */
  display?: DisplayOptions;
  /**
   * The desired authentication behaviour.
   * - `none`: User is not prompted to sign in.
   * - `login`: Prompt the user to log in even if the user is already authenticated.
   * - `consent`: Prompt the user for consent.
   * - `select_account`: Prompt the user to sign in.
   * - `create`: Prompt the user to sign up.
   */
  prompt?: Prompt;
  /** The request uri obtained from pushed authorization request. When this parameter is set, all other properties are ignored */
  requestUri?: string;
  /** Space-separated list of resources the access token should be scoped to */
  resource?: string;
}

/** Defines the parameters received in the callback URL after authorization */
export interface CallbackParams {
  /** State received from the authorization server */
  state?: string;
  /** Error message specifying the cause of authentication failure */
  error?: string;
  /** Explanation of the reason for authentication failure */
  errorDescription?: string;
  /** Authorization code received from the callback */
  code?: string;
  /** Access token received from the callback */
  accessToken?: string;
  /** Expiry of the access token in seconds */
  expiresIn?: number;
  /** ID token received from the callback */
  idToken?: string;
  /** Refresh token received from the callback */
  refreshToken?: string;
  /** A string that represents the End-User's login state. The `sessionState` can be used to track the user's session in the frontend */
  sessionState?: string;
}

/** Represents a JSON Web Key (JWK) */
export interface Jwk {
  kty: string;
  alg?: string;
  key_ops?: string[];
  ext?: boolean;
  use?: string;
  x5c?: string[];
  x5t?: string;
  'x5t#S256'?: string;
  x5u?: string;
  kid?: string;
  crv?: string;
  d?: string;
  dp?: string;
  dq?: string;
  e?: string;
  k?: string;
  n?: string;
  oth?: {
    d?: string;
    r?: string;
    t?: string;
  }[];
  p?: string;
  q?: string;
  qi?: string;
  x?: string;
  y?: string;
}

/** A set of public JSON Web Keys that are used to verify JSON Web Tokens */
export interface Jwks {
  /** List of JWKs in this JWKS */
  keys: Jwk[];
}

type KnownKeys<T> = {
  [K in keyof T]: string extends K ? never : number extends K ? never : K;
} extends { [_ in keyof T]: infer U }
  ? object extends U
    ? never
    : U
  : never;

type Override<T1, T2> = Omit<T1, keyof Omit<T2, keyof KnownKeys<T2>>> & T2;

/**
 * Address type
 */
export type Address<ExtendedAddress extends object = Record<string, unknown>> =
  Override<
    {
      formatted?: string;
      street_address?: string;
      locality?: string;
      region?: string;
      postal_code?: string;
      country?: string;
    },
    ExtendedAddress
  >;

/**
 * Userinfo response type
 */
export type UserinfoResponse<
  UserInfo extends object = Record<string, unknown>,
  ExtendedAddress extends object = Record<string, unknown>,
> = Override<
  {
    sub: string;
    groups?: Group[];
    name?: string;
    given_name?: string;
    family_name?: string;
    middle_name?: string;
    nickname?: string;
    preferred_username?: string;
    profile?: string;
    picture?: string;
    website?: string;
    email?: string;
    email_verified?: boolean;
    gender?: string;
    birthdate?: string;
    zoneinfo?: string;
    locale?: string;
    phone_number?: string;
    phone_number_verified?: boolean;
    updated_at?: number;
    address?: Address<ExtendedAddress>;
  },
  UserInfo
>;

/** User's group type. The group can be a group object with `id` and `name` or group name or group id */
export type Group = { id: string; name: string } | string;

/** Represents a MonoCloudUser */
export interface MonoCloudUser extends UserinfoResponse {
  amr?: string[];
  idp?: string;
}

export interface AccessToken {
  /**
   * The access token associated with the session.
   */
  accessToken: string;

  /**
   * The expiration timestamp of the access token (in epoch).
   */
  accessTokenExpiration: number;

  /**
   * The scopes granted by the access token.
   */
  scopes: string;

  /**
   * Optional. The resource associated with the access token.
   */
  resource?: string;

  /**
   * Optional. The requested scopes.
   */
  requestedScopes?: string;
}

/**
 * Represents a session containing user information, tokens, and additional custom properties.
 */
export interface MonoCloudSession {
  /**
   * Information about the authenticated user, typically claims obtained from an ID token or the 'userinfo' endpoint.
   */
  user: MonoCloudUser;

  /**
   * Optional. The ID token associated with the session.
   */
  idToken?: string;

  /* The default scopes authorized for the session */
  authorizedScopes?: string;

  /**
   * Optional. The access tokens associated with the session.
   */
  accessTokens?: AccessToken[];

  /**
   * Optional. The refresh token associated with the session.
   */
  refreshToken?: string;

  /**
   * Additional custom properties that can be added to the session.
   */
  [key: string]: unknown;
}

/** Claims obtained from ID token */
export interface IdTokenClaims extends UserinfoResponse {
  acr?: string;
  amr?: string[];
  at_hash?: string;
  aud: string | string[];
  auth_time?: number;
  azp?: string;
  c_hash?: string;
  exp: number;
  iat: number;
  iss: string;
  nonce?: string;
  s_hash?: string;
  sub: string;
  [key: string]: unknown;
}

/** Token endpoint response */
export interface Tokens {
  /** Access token */
  access_token: string;
  /** Refresh token */
  refresh_token?: string;
  /** ID token */
  id_token?: string;
  /** Scopes requested */
  scope?: string;
  /** Access token expiry in seconds */
  expires_in?: number;
  /** Type of access token */
  token_type?: string;
}

/**
 * Possible values for the authenticators.
 */
export type Authenticators =
  | 'password'
  | 'passkey'
  | 'email'
  | 'phone'
  | 'google'
  | 'apple'
  | 'facebook'
  | 'microsoft'
  | 'github'
  | 'gitlab'
  | 'discord'
  | 'twitter'
  | 'linkedin'
  | 'xero';

export type JWSAlgorithm =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES384'
  | 'ES512';

export interface JwsHeaderParameters {
  alg: JWSAlgorithm;
  kid?: string;
  typ?: string;
  crit?: string[];
  jwk?: Jwk;
}

/** Stores various parameters used in the authentication request */
export interface AuthState {
  /**
   * A unique value used to maintain state between the sign-in request and the callback.
   */
  state: string;

  /**
   * A unique value used to prevent replay attacks in OAuth flows.
   */
  nonce: string;

  /**
   * Optional. A code verifier used in PKCE (Proof Key for Code Exchange) flow.
   */
  codeVerifier?: string;

  /**
   * Optional. The maximum age (in seconds) of the session.
   */
  maxAge?: number;

  /**
   * Optional. Space-separated list of resources to scope the access token to
   */
  resource?: string;

  /**
   * Space-separated list of scopes to request
   */
  scopes: string;
}

/** Parameters for creating the sign out URL. */
export interface EndSessionParameters {
  /** The ID token of the user to be used to hint the user signing out */
  idToken?: string;
  /** The URL the authorization server should redirect the user to after a successful sign out. This URL has to be registered in the client's sign out URL section. */
  postLogoutRedirectUri?: string;
  /** A random string to be sent to the authorization server when the `postLogoutRedirectUri` is set. */
  state?: string;
}

/** Authorization server metadata */
export interface IssuerMetadata {
  issuer: string;
  jwks_uri: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  end_session_endpoint: string;
  check_session_iframe: string;
  revocation_endpoint: string;
  introspection_endpoint: string;
  device_authorization_endpoint: string;
  pushed_authorization_request_endpoint?: string;
  frontchannel_logout_supported: boolean;
  frontchannel_logout_session_supported: boolean;
  backchannel_logout_supported: boolean;
  backchannel_logout_session_supported: boolean;
  scopes_supported: string[];
  claims_supported: string[];
  grant_types_supported: string[];
  response_types_supported: string[];
  response_modes_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  id_token_signing_alg_values_supported: string[];
  subject_types_supported: string[];
  code_challenge_methods_supported: string[];
  request_parameter_supported: boolean;
  request_uri_parameter_supported: boolean;
  require_pushed_authorization_requests: boolean;
  request_object_signing_alg_values_supported: string[];
}

export interface RefreshGrantOptions {
  /**
   * Space-separated list of resources to scope the access token to
   */
  resource?: string;

  /**
   * Space-separated list of scopes to request
   */
  scopes?: string;
}

/** Options used for authenticating a user with authorization code */
export interface AuthenticateOptions {
  /** The PKCE Code verifier used for authentication */
  codeVerifier?: string;
  /** When enabled, the userinfo is fetched and populated into the user object. @defaultValue false */
  fetchUserInfo?: boolean;
  /** Whether to validate the ID token or not. @defaultValue true */
  validateIdToken?: boolean;
  /** Jwks to validate the ID token with. JWKS is fetched from the authorization server if `jwks` is not provided. */
  jwks?: Jwks;
  /** Nonce to be validated against the claims from the ID token */
  idTokenNonce?: string;
  /** Allowed max age in seconds */
  idTokenMaxAge?: number;
  /** Used to adjust the current time to align with the authorization server time */
  idTokenClockSkew?: number;
  /** Allowed clock tolerance when checking date-time claims */
  idTokenClockTolerance?: number;
  /**
   *  List of ID token claims to remove.
   */
  filteredIdTokenClaims?: string[];
  /**
   * A callback function invoked before creating or updating the user session.
   */
  onSessionCreating?: OnSessionCreating;
}

/** Options for refreshing MonoCloudSession */
export interface RefreshSessionOptions {
  /** When enabled, the userinfo is fetched and populated into the user object. @defaultValue false */
  fetchUserInfo?: boolean;
  /** Whether to validate the ID token or not. @defaultValue true */
  validateIdToken?: boolean;
  /** Jwks to validate the ID token with. JWKS is fetched from the authorization server if `jwks` is not provided. */
  jwks?: Jwks;
  /** Used to adjust the current time to align with the authorization server time */
  idTokenClockSkew?: number;
  /** Allowed clock tolerance when checking date-time claims */
  idTokenClockTolerance?: number;
  /** Options for the refresh grant */
  refreshGrantOptions?: RefreshGrantOptions;
  /**
   *  List of ID token claims to remove.
   */
  filteredIdTokenClaims?: string[];
  /**
   * A callback function invoked before creating or updating the user session.
   */
  onSessionCreating?: OnSessionCreating;
}

/** Options for refetching userinfo */
export interface RefetchUserInfoOptions {
  /**
   * A callback function invoked before creating or updating the user session.
   */
  onSessionCreating?: OnSessionCreating;
}

/** Client authentication methods supported */
export type ClientAuthMethod =
  | 'client_secret_basic'
  | 'client_secret_post'
  | 'client_secret_jwt'
  | 'private_key_jwt';

/** Parameters for Pushed Authorization Request (PAR) */
export type PushedAuthorizationParams = Omit<AuthorizationParams, 'requestUri'>;

/** Options to initialize the MonoCloudClient */
export interface MonoCloudClientOptions {
  /**
   * Client secret used for authentication.
   *
   * When the client authentication method is `client_secret_jwt` and a plain-text secret is provided,
   * the default signing algorithm is `HS256`.
   *
   * To use a different algorithm, supply a symmetric JSON Web Key (JWK) object (`kty = "oct"`)
   * that specifies the desired algorithm in its `alg` property.
   */

  clientSecret?: string | Jwk;
  /** Client authentication method */
  clientAuthMethod?: ClientAuthMethod;
  /** ID token signing algorithm. @defaultValue - RS256 */
  idTokenSigningAlgorithm?: JWSAlgorithm;
  /**
   * Jwks Cache Duration
   *
   * Time in seconds to cache the JWKS document after it is fetched
   *
   * @defaultValue 60
   *
   * */
  jwksCacheDuration?: number;

  /**
   * Metadata Cache Duration
   *
   * Time in seconds to cache the metadata document after it is fetched.
   *
   * @defaultValue 60
   * */
  metadataCacheDuration?: number;
}

/**
 * Response from a Pushed Authorization Request (PAR) endpoint.
 */
export interface ParResponse {
  /**
   * URI reference for the pushed authorization request.
   */
  request_uri: string;

  /**
   * Request URI lifetime in seconds.
   */
  expires_in: number;
}

/**
 * Defines a callback function to be executed when a new session is being created or updated.
 * This function receives parameters related to the session being created,
 * including the session object itself, optional ID token and user information claims.
 *
 * @param session - The Session object being created.
 * @param idToken - Optional. Claims from the ID token received during authentication.
 * @param userInfo - Optional. Claims from the user information received during authentication.
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
  userInfo?: UserinfoResponse
) => Promise<void> | void;
