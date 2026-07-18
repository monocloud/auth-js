/**
 * Supported OAuth 2.0 / OpenID Connect response types.
 *
 * Response types determine which artifacts are returned from the authorization endpoint during authentication.
 *
 * > Modern applications should prefer the Authorization Code Flow (`code`) with PKCE. Implicit flow variants are included for compatibility with legacy or specialized scenarios.
 *
 * @category Types (Enums)
 */
export type ResponseTypes =
  /**
   * Authorization Code Flow (recommended). Returns an authorization code that is exchanged for tokens on the server-side.
   */
  | 'code'

  /**
   * Implicit Flow returning an access token directly from the authorization endpoint.
   */
  | 'token'

  /**
   * Implicit Flow returning an ID token.
   */
  | 'id_token'

  /**
   * Implicit Flow returning both an ID token and an access token.
   */
  | 'id_token token'

  /**
   * Hybrid Flow returning an authorization code and an ID token.
   */
  | 'code id_token'

  /**
   * Hybrid Flow returning an authorization code and an access token.
   */
  | 'code token'

  /**
   * Hybrid Flow returning an authorization code, ID token, and access token.
   */
  | 'code id_token token';

/**
 * Supported PKCE (Proof Key for Code Exchange) code challenge methods.
 *
 * PKCE protects authorization code flows by binding the authorization request to the token exchange using a cryptographic verifier.
 *
 * @category Types (Enums)
 */
export type CodeChallengeMethod =
  /**
   * Uses the code verifier directly as the challenge. Not recommended for production use.
   */
  | 'plain'

  /**
   * Uses a SHA-256 hash of the code verifier.
   */
  | 'S256';

/**
 * Supported OpenID Connect `display` parameter values.
 *
 * The display parameter hints to the authorization server how the authentication or consent UI should be presented to the user.
 *
 * @category Types (Enums)
 */
export type DisplayOptions =
  /**
   * Full-page authentication experience in the browser.
   */
  | 'page'

  /**
   * Authentication optimized for popup windows.
   */
  | 'popup'

  /**
   * Authentication optimized for touch-based devices.
   */
  | 'touch'

  /**
   * Authentication optimized for legacy mobile or constrained browsers.
   */
  | 'wap';

/**
 * Supported OAuth 2.0 / OpenID Connect `response_mode` values.
 *
 * The response mode determines how authorization results are returned from the authorization endpoint to the client application.
 *
 * @category Types (Enums)
 */
export type ResponseModes =
  /**
   * Returns authorization results using an HTTP POST request with parameters encoded in the request body.
   */
  | 'form_post'

  /**
   * Returns authorization results as URL query parameters.
   */
  | 'query'

  /**
   * Returns authorization results in the URL fragment.
   */
  | 'fragment';

/**
 * Supported OpenID Connect `prompt` parameter values.
 *
 * The `prompt` parameter controls whether the authorization server should force specific user interactions during authentication.
 *
 * @category Types (Enums)
 */
export type Prompt =
  /**
   * Do not display any authentication or consent UI.
   */
  | 'none'

  /**
   * Forces the user to re-authenticate even if an active session exists.
   */
  | 'login'

  /**
   * Forces the consent screen to be displayed to the user.
   */
  | 'consent'

  /**
   * Prompts the user to choose an account when multiple sessions exist.
   */
  | 'select_account'

  /**
   * Prompts the user to create a new account (sign-up flow).
   */
  | 'create';

/**
 * Parameters used to construct an OAuth 2.0 / OpenID Connect authorization request.
 *
 * @category Types
 */
export interface AuthorizationParams {
  /**
   * A cryptographically random value used to maintain request state
   * and protect against CSRF attacks.
   */
  state?: string;

  /**
   * Space-separated list of scopes requested during authentication.
   */
  scopes?: string;

  /**
   * The redirect URI where the authorization server sends the user after authentication completes.
   */
  redirectUri?: string;

  /**
   * Determines which artifacts are returned from the authorization endpoint.
   */
  responseType?: ResponseTypes;

  /**
   * PKCE code challenge derived from the code verifier. Used to secure authorization code exchanges.
   */
  codeChallenge?: string;

  /**
   * Method used to generate the PKCE code challenge.
   */
  codeChallengeMethod?: CodeChallengeMethod;

  /**
   * Hint to the authorization server indicating which authenticator or connection should be used.
   */
  authenticatorHint?: Authenticators;

  /**
   * Maximum acceptable time (in seconds) since the user last authenticated. If exceeded, the user may be required to sign in again.
   */
  maxAge?: number;

  /**
   * Hint identifying the user (for example, email or username). Used to prefill or optimize the sign-in experience.
   */
  loginHint?: string;

  /**
   * A signed JWT containing authorization request parameters.
   */
  request?: string;

  /**
   * Specifies how the authorization response is returned to the client.
   */
  responseMode?: ResponseModes;

  /**
   * Authentication Context Class Reference (ACR) values requesting specific authentication assurance levels or methods.
   */
  acrValues?: string[];

  /**
   * A cryptographically random value included in the ID token to prevent replay attacks.
   */
  nonce?: string;

  /**
   * Preferred UI language.
   */
  uiLocales?: string;

  /**
   * Preferred display mode for the authentication UI.
   */
  display?: DisplayOptions;

  /**
   * Controls authentication interaction behavior. For example, forcing login or consent.
   */
  prompt?: Prompt;

  /**
   * URI referencing a previously created authorization request (typically via Pushed Authorization Requests — PAR).
   *
   * When set, other authorization parameters may be ignored.
   */
  requestUri?: string;

  /**
   * Space-separated list of resource indicators that scope the issued access token.
   */
  resource?: string;
}

/**
 * Parameters used to construct an OAuth 2.0 / OpenID Connect device authorization request.
 *
 * @category Types
 */
export interface DeviceAuthorizationParams {
  /**
   * Space-separated list of scopes requested during authentication.
   */
  scopes?: string;

  /**
   * Space-separated list of resource indicators that scope the issued access token.
   */
  resource?: string;
}

/**
 * Response from the Device Authorization Request.
 *
 * @category Types
 */
export interface DeviceAuthorizationResponse {
  /**
   * The device verification code.
   */
  device_code: string;

  /**
   * The end-user verification code.
   */
  user_code: string;

  /**
   * The end-user verification URI.
   */
  verification_uri: string;

  /**
   * A verification URI that includes the "user_code" in the query parameter.
   */
  verification_uri_complete?: string;

  /**
   * The lifetime in seconds of the "device_code" and "user_code".
   */
  expires_in: number;

  /**
   * The minimum amount of time in seconds that the client SHOULD wait between polling requests to the token endpoint.
   */
  interval?: number;
}

/**
 * Parameters returned to the application after the authorization server redirects the user back to the callback URL.
 *
 * @category Types
 */
export interface CallbackParams {
  /**
   * The state value originally sent in the authorization request. Used to validate request integrity and prevent CSRF attacks.
   */
  state?: string;

  /**
   * Error code returned when authorization fails.
   */
  error?: string;

  /**
   * Human-readable description providing additional information about the authorization error.
   */
  errorDescription?: string;

  /**
   * Access token scopes (Implicit Flow)
   */
  scope?: string;

  /**
   * Authorization code returned when using the Authorization Code Flow.
   */
  code?: string;

  /**
   * Access token returned directly by implicit or hybrid flows.
   */
  accessToken?: string;

  /**
   * Lifetime of the access token in seconds.
   */
  expiresIn?: number;

  /**
   * ID token issued by the authorization server.
   */
  idToken?: string;

  /**
   * Refresh token issued during authorization (if enabled).
   */
  refreshToken?: string;

  /**
   * OIDC session state value used for session monitoring and front-channel session management.
   */
  sessionState?: string;
}

/**
 * Represents a JSON Web Key (JWK) as defined by RFC 7517.
 *
 * A JWK describes a cryptographic key used to verify or encrypt JSON Web Tokens (JWTs) as obtained from the JWKS (JSON Web Key Set) endpoint exposed by the authorization server.
 *
 * The available properties depend on the key type (`kty`).
 *
 * @category Types
 */
export interface Jwk {
  /**
   * Key type (for example: `RSA`, or `EC`).
   */
  kty: string;

  /**
   * Intended algorithm for the key (for example: `RS256`).
   */
  alg?: string;

  /**
   * Allowed operations for the key (e.g. `sign`, `verify`, `encrypt`).
   */
  key_ops?: string[];

  /**
   * Indicates whether the key is extractable.
   */
  ext?: boolean;

  /**
   * Public key use (`sig` for signature or `enc` for encryption).
   */
  use?: string;

  /**
   * X.509 certificate chain.
   */
  x5c?: string[];

  /**
   * X.509 certificate SHA-1 thumbprint.
   */
  x5t?: string;

  /**
   * X.509 certificate SHA-256 thumbprint.
   */
  'x5t#S256'?: string;

  /**
   * URL referencing the X.509 certificate.
   */
  x5u?: string;

  /**
   * Key identifier used to match keys during verification.
   */
  kid?: string;

  /**
   * Elliptic curve name (for example: `P-256`).
   */
  crv?: string;

  /**
   * X coordinate for EC public keys.
   */
  x?: string;

  /**
   * Y coordinate for EC public keys.
   */
  y?: string;

  /**
   * RSA modulus.
   */
  n?: string;

  /**
   * RSA public exponent.
   */
  e?: string;

  /**
   * RSA private exponent.
   */
  d?: string;

  /**
   * RSA first prime factor.
   */
  p?: string;

  /**
   * RSA second prime factor.
   */
  q?: string;

  /**
   * RSA first factor CRT exponent.
   */
  dp?: string;

  /**
   * RSA second factor CRT exponent.
   */
  dq?: string;

  /**
   * RSA CRT coefficient.
   */
  qi?: string;

  /**
   * Additional prime information (multi-prime RSA).
   */
  oth?: {
    d?: string;
    r?: string;
    t?: string;
  }[];

  /**
   * Symmetric key value (base64url encoded).
   */
  k?: string;
}

/**
 * Represents a JSON Web Key Set (JWKS).
 *
 * A JWKS is a collection of public JSON Web Keys used to verify signatures of JSON Web Tokens (JWTs).
 *
 * @category Types
 */
export interface Jwks {
  /**
   * The list of public keys contained in this key set.
   */
  keys: Jwk[];
}

/**
 * Represents a postal address as defined by the OpenID Connect standard `address` claim.
 *
 * @category Types
 */
export interface Address {
  /**
   * Full mailing address formatted for display or mailing labels.
   */
  formatted?: string;

  /**
   * Full street address component, which may include house number, street name, apartment, suite, or unit information.
   */
  street_address?: string;

  /**
   * City or locality component.
   */
  locality?: string;

  /**
   * State, province, or region component.
   */
  region?: string;

  /**
   * Postal or ZIP code.
   */
  postal_code?: string;

  /**
   * Country name or ISO country code.
   */
  country?: string;

  /**
   * Additional provider-specific address fields.
   */
  [key: string]: unknown;
}

/**
 * Represents the OpenID Connect **UserInfo** response.
 *
 * @typeParam TAddress - The shape of the `address` claim. Defaults to {@link Address}.
 *
 * @category Types
 */
export interface UserinfoResponse<TAddress extends Address = Address> {
  /**
   * Subject identifier - a unique, stable identifier for the user within the issuer.
   */
  sub: string;

  /**
   * Group memberships for the user.
   */
  groups?: Group[];

  /**
   * Full name of the user (e.g. "Jane Doe").
   */
  name?: string;

  /**
   * Given name(s) / first name.
   */
  given_name?: string;

  /**
   * Surname(s) / last name.
   */
  family_name?: string;

  /**
   * Middle name(s).
   */
  middle_name?: string;

  /**
   * Casual name used by the user.
   */
  nickname?: string;

  /**
   * Preferred username.
   */
  preferred_username?: string;

  /**
   * URL of the user's profile page.
   */
  profile?: string;

  /**
   * URL of the user's profile picture.
   */
  picture?: string;

  /**
   * URL of the user's website.
   */
  website?: string;

  /**
   * Email address.
   */
  email?: string;

  /**
   * Whether the email address has been verified by the provider.
   */
  email_verified?: boolean;

  /**
   * Gender.
   */
  gender?: string;

  /**
   * Birthday.
   */
  birthdate?: string;

  /**
   * Time zone name.
   */
  zoneinfo?: string;

  /**
   * Locale.
   */
  locale?: string;

  /**
   * Phone number (formatted in E.164 standard).
   */
  phone_number?: string;

  /**
   * Whether the phone number has been verified by the provider.
   */
  phone_number_verified?: boolean;

  /**
   * Time the user's information was last updated (seconds since epoch).
   */
  updated_at?: number;

  /**
   * Postal address.
   */
  address?: TAddress;

  /**
   * Additional provider-specific claims.
   */
  [key: string]: unknown;
}

/**
 * Represents a user group included in the authenticated session.
 *
 * @category Types
 */
export type Group =
  /**
   * Structured group representation.
   */
  | {
      /**  Group identifier. */
      id: string;
      /** Group name. */
      name: string;
    }

  /**
   * Group identifier or group name.
   */
  | string;

/**
 * Represents the authenticated user stored in a MonoCloud session.
 *
 * @category Types
 */
export interface MonoCloudUser extends UserinfoResponse {
  /**
   * Authentication Methods References (AMR). Indicates how the user authenticated.
   */
  amr?: string[];

  /**
   * Identity Provider (IdP) identifier. Specifies the upstream provider used to authenticate the user.
   */
  idp?: string;
}

/**
 * Represents an OAuth 2.0 access token and its associated metadata.
 *
 * @category Types
 */
export interface AccessToken {
  /**
   * The issued access token.
   */
  accessToken: string;

  /**
   * The expiration time of the access token (Unix epoch, in seconds).
   */
  accessTokenExpiration: number;

  /**
   * Space-separated list of scopes granted to the access token.
   *
   * These represent the effective permissions approved by the authorization server.
   */
  scopes: string;

  /**
   * Optional resource (audience) that the access token is scoped for.
   */
  resource?: string;

  /**
   * Optional space-separated list of scopes originally requested during token acquisition.
   */
  requestedScopes?: string;
}

/**
 * Represents an authenticated session, containing the authenticated user profile along with the tokens and metadata issued during authentication.
 *
 * @category Types
 */
export interface MonoCloudSession {
  /**
   * The authenticated user profile, typically derived from ID token claims and/or the `UserInfo` endpoint.
   */
  user: MonoCloudUser;

  /**
   * Optional ID token issued during authentication.
   */
  idToken?: string;

  /**
   * Space-separated list of scopes authorized for the session.
   */
  authorizedScopes?: string;

  /**
   * Access tokens associated with the session.
   *
   * Multiple tokens may exist when access tokens are issued for different resources or scope sets.
   */
  accessTokens?: AccessToken[];

  /**
   * Optional refresh token used to obtain new access tokens without requiring the user to re-authenticate.
   */
  refreshToken?: string;

  /**
   * Additional custom properties attached to the session.
   *
   * These may be added via hooks such as `onSessionCreating`.
   */
  [key: string]: unknown;
}

/**
 * Standard JWT claims shared between ID tokens and access tokens.
 *
 * @category Types
 */
export interface JwtClaims {
  /**
   * Issuer identifier - the authorization server that issued the token.
   */
  iss: string;

  /**
   * Subject identifier — uniquely identifies the authenticated user.
   */
  sub: string;

  /**
   * Intended audience(s) of the token.
   */
  aud: string | string[];

  /**
   * Expiration time of the token (Unix epoch seconds).
   */
  exp: number;

  /**
   * Time at which the token was issued (Unix epoch seconds).
   */
  iat: number;

  /**
   * Not-before time (Unix epoch seconds).
   */
  nbf?: number;

  /**
   * Additional custom or provider-specific claims.
   */
  [key: string]: unknown;
}

/**
 * Standard OpenID Connect ID Token claims.
 *
 * @category Types
 */
export interface IdTokenClaims extends UserinfoResponse, JwtClaims {
  /**
   * Authentication Context Class Reference. Indicates the assurance level of the authentication performed.
   */
  acr?: string;

  /**
   * Authentication Methods References. Lists the authentication methods used (for example: `pwd`, `mfa`, `otp`).
   */
  amr?: string[];

  /**
   * Access token hash. Used to validate access tokens returned alongside the ID token.
   */
  at_hash?: string;

  /**
   * Time when the end-user authentication occurred (Unix epoch seconds).
   */
  auth_time?: number;

  /**
   * Authorized party - identifies the client to which the ID token was issued.
   */
  azp?: string;

  /**
   * Authorization code hash. Used to validate authorization codes returned with hybrid flows.
   */
  c_hash?: string;

  /**
   * Nonce value used to associate the authentication request with the issued ID token and prevent replay attacks.
   */
  nonce?: string;

  /**
   * State hash (used in some hybrid flow validations).
   */
  s_hash?: string;
}

/**
 * Claims contained in a validated OAuth 2.0 access token.
 *
 * @category Types
 */
export interface AccessTokenClaims extends JwtClaims {
  /**
   * OAuth scope associated with the token.
   */
  scope?: string;

  /**
   * Client ID of the application the token was issued to.
   */
  client_id?: string;

  /**
   * JWT ID (unique identifier for the token).
   */
  jti?: string;
}

/**
 * OAuth 2.0 / OpenID Connect token endpoint response.
 *
 * @category Types
 */
export interface Tokens {
  /**
   * Access token issued by the authorization server.
   */
  access_token: string;

  /**
   * Optional refresh token used to obtain new access tokens without requiring user re-authentication.
   */
  refresh_token?: string;

  /**
   * Optional ID token containing authentication claims about the user.
   */
  id_token?: string;

  /**
   * Space-separated list of scopes granted for the access token.
   */
  scope?: string;

  /**
   * Lifetime of the access token (in seconds) from the time the response was issued.
   */
  expires_in?: number;

  /**
   * Token type issued.
   */
  token_type?: string;
}

/**
 * Supported authentication methods and identity providers.
 *
 * @category Types (Enums)
 */
export type Authenticators =
  /**
   * Username/password authentication.
   */
  | 'password'

  /**
   * Passkey (WebAuthn / FIDO2) authentication.
   */
  | 'passkey'

  /**
   * Email-based authentication (magic link or OTP).
   */
  | 'email'

  /**
   * Phone-based authentication (SMS OTP).
   */
  | 'phone'

  /**
   * Google identity provider.
   */
  | 'google'

  /**
   * Apple identity provider.
   */
  | 'apple'

  /**
   * Facebook identity provider.
   */
  | 'facebook'

  /**
   * Microsoft identity provider.
   */
  | 'microsoft'

  /**
   * GitHub identity provider.
   */
  | 'github'

  /**
   * GitLab identity provider.
   */
  | 'gitlab'

  /**
   * Discord identity provider.
   */
  | 'discord'

  /**
   * Twitter (X) identity provider.
   */
  | 'twitter'

  /**
   * LinkedIn identity provider.
   */
  | 'linkedin'

  /**
   * Xero identity provider.
   */
  | 'xero';

/**
 * Supported JSON Web Signature (JWS) algorithms used to sign tokens.
 *
 * These algorithms define how tokens issued by MonoCloud are cryptographically signed and verified. The expected algorithm should match the configuration of your MonoCloud application.
 *
 * @category Types (Enums)
 */
export type SecurityAlgorithms =
  /**
   * RSA using SHA-256.
   *
   * Default and most commonly used signing algorithm.
   */
  | 'RS256'

  /**
   * RSA using SHA-384.
   */
  | 'RS384'

  /**
   * RSA using SHA-512.
   */
  | 'RS512'

  /**
   * RSA-PSS using SHA-256.
   *
   * Provides stronger cryptographic padding than RS256.
   */
  | 'PS256'

  /**
   * RSA-PSS using SHA-384.
   */
  | 'PS384'

  /**
   * RSA-PSS using SHA-512.
   */
  | 'PS512'

  /**
   * ECDSA using P-256 curve and SHA-256.
   *
   * Produces smaller tokens and faster verification.
   */
  | 'ES256'

  /**
   * ECDSA using P-384 curve and SHA-384.
   */
  | 'ES384'

  /**
   * ECDSA using P-521 curve and SHA-512.
   */
  | 'ES512';

/**
 * Parameters contained in a JSON Web Signature (JWS) header.
 *
 * @category Types
 */
export interface JwsHeaderParameters {
  /**
   * The cryptographic algorithm used to sign the token.
   */
  alg: SecurityAlgorithms;

  /**
   * Identifier of the key used to sign the token.
   */
  kid?: string;

  /**
   * The token type.
   */
  typ?: string;

  /**
   * List of header parameters that are marked as critical and must be understood by the token processor.
   */
  crit?: string[];

  /**
   * An embedded JSON Web Key (JWK) containing the signing key.
   */
  jwk?: Jwk;
}

/**
 * Represents the authentication transaction state stored between the authorization request and the callback.
 *
 * @category Types
 */
export interface AuthState {
  /**
   * A unique value used to correlate the authorization request with the callback and protect against CSRF attacks.
   */
  state: string;

  /**
   * A cryptographic value used to associate the ID token with the original authentication request and prevent replay attacks.
   */
  nonce: string;

  /**
   * Optional. PKCE code verifier used to validate the authorization code exchange.
   */
  codeVerifier?: string;

  /**
   * Optional. Maximum allowed time (in seconds) since the user's last authentication.
   */
  maxAge?: number;

  /**
   * Optional. Space-separated list of resource indicators requested for the access token.
   */
  resource?: string;

  /**
   * Space-separated list of scopes requested during authorization.
   */
  scopes: string;
}

/**
 * Parameters used to construct an OpenID Connect end-session (sign-out) request.
 *
 * @category Types
 */
export interface EndSessionParameters {
  /**
   * ID token hint identifying the session to terminate.
   *
   * When provided, the authorization server can use this value to determine which user session should be signed out.
   */
  idToken?: string;

  /**
   * The URL the authorization server should redirect the user to after a successful sign-out.
   */
  postLogoutRedirectUri?: string;

  /**
   * Optional state value returned to the application after sign-out.
   */
  state?: string;
}

/**
 * OpenID Connect Discovery metadata published by the authorization server.
 *
 * @category Types
 */
export interface IssuerMetadata {
  /**
   * The issuer identifier for the authorization server.
   */
  issuer: string;

  /**
   * JSON Web Key Set (JWKS) endpoint used to obtain signing keys.
   */
  jwks_uri: string;

  /**
   * Authorization endpoint used to initiate authentication requests.
   */
  authorization_endpoint: string;

  /**
   * Token endpoint used to exchange authorization codes for tokens.
   */
  token_endpoint: string;

  /**
   * UserInfo endpoint used to retrieve user profile claims.
   */
  userinfo_endpoint: string;

  /**
   * End-session endpoint used to initiate logout.
   */
  end_session_endpoint: string;

  /**
   * Session management iframe endpoint.
   */
  check_session_iframe: string;

  /**
   * Token revocation endpoint.
   */
  revocation_endpoint: string;

  /**
   * Token introspection endpoint.
   */
  introspection_endpoint: string;

  /**
   * Device Authorization Grant endpoint.
   */
  device_authorization_endpoint: string;

  /**
   * Pushed Authorization Request (PAR) endpoint.
   */
  pushed_authorization_request_endpoint?: string;

  /**
   * Indicates support for front-channel logout.
   */
  frontchannel_logout_supported: boolean;

  /**
   * Indicates front-channel logout session support.
   */
  frontchannel_logout_session_supported: boolean;

  /**
   * Indicates support for back-channel logout.
   */
  backchannel_logout_supported: boolean;

  /**
   * Indicates back-channel logout session support.
   */
  backchannel_logout_session_supported: boolean;

  /**
   * OAuth scopes supported by the authorization server.
   */
  scopes_supported: string[];

  /**
   * Claims that may be returned in tokens or UserInfo responses.
   */
  claims_supported: string[];

  /**
   * Supported OAuth grant types.
   */
  grant_types_supported: string[];

  /**
   * Supported OAuth/OIDC response types.
   */
  response_types_supported: string[];

  /**
   * Supported response modes.
   */
  response_modes_supported: string[];

  /**
   * Supported authentication methods for the token endpoint.
   */
  token_endpoint_auth_methods_supported: string[];

  /**
   * Supported signing algorithms for ID tokens.
   */
  id_token_signing_alg_values_supported: string[];

  /**
   * Supported subject identifier types.
   */
  subject_types_supported: string[];

  /**
   * Supported PKCE code challenge methods.
   */
  code_challenge_methods_supported: string[];

  /**
   * Indicates support for request objects passed by value.
   */
  request_parameter_supported: boolean;

  /**
   * Indicates support for request objects passed by reference (request_uri).
   */
  request_uri_parameter_supported: boolean;

  /**
   * Indicates whether PAR is required for authorization requests.
   */
  require_pushed_authorization_requests: boolean;

  /**
   * Supported signing algorithms for request objects.
   */
  request_object_signing_alg_values_supported: string[];
}

/**
 * Options used when exchanging a refresh token for a new access token.
 *
 * These parameters allow requesting an access token scoped to specific resources or scopes that were previously authorized by the user.
 *
 * @category Types
 */
export interface RefreshGrantOptions {
  /**
   * Space-separated list of resource indicators that the new access token should be issued for.
   *
   * The requested resources must have been previously granted during the original authorization flow.
   */
  resource?: string;

  /**
   * Space-separated list of scopes to request for the refreshed access token.
   *
   * The requested scopes must have been granted during the original authorization flow.
   */
  scopes?: string;
}

/**
 * Options used when authenticating a user via the Authorization Code flow.
 *
 * @category Types
 */
export interface AuthenticateOptions {
  /**
   * PKCE code verifier associated with the authorization request.
   */
  codeVerifier?: string;

  /**
   * When enabled, user profile data is fetched from the UserInfo endpoint and merged into the session user object.
   * @defaultValue false
   */
  fetchUserInfo?: boolean;

  /**
   * Determines whether the ID token signature and claims should be validated. Disabling validation is not recommended except for advanced or controlled environments.
   * @defaultValue true
   */
  validateIdToken?: boolean;

  /**
   * JSON Web Key Set used to validate the ID token signature.
   *
   * If not provided, the JWKS is automatically fetched from the authorization server metadata.
   */
  jwks?: Jwks;

  /**
   * Nonce value expected in the ID token. Used to prevent replay attacks.
   */
  idTokenNonce?: string;

  /**
   * Maximum allowed authentication age (in seconds) for the ID token.
   */
  idTokenMaxAge?: number;

  /**
   * Clock skew adjustment (in seconds) applied when validating ID token timestamps against the authorization server.
   */
  idTokenClockSkew?: number;

  /**
   * Additional allowed clock tolerance (in seconds) when validating time-based ID token claims such as `exp`, `iat`, and `nbf`.
   */
  idTokenClockTolerance?: number;

  /**
   * List of ID token claims to remove before storing the session.
   */
  filteredIdTokenClaims?: string[];

  /**
   * Callback invoked before a session is created or updated. Allows customization or enrichment of the session.
   */
  onSessionCreating?: OnSessionCreating;
}

/**
 * Options used when refreshing an existing MonoCloud session.
 *
 * @category Types
 */
export interface RefreshSessionOptions {
  /**
   * When enabled, user profile data is fetched from the UserInfo endpoint and merged into the session user object.
   * @defaultValue false
   */
  fetchUserInfo?: boolean;

  /**
   * Determines whether the ID token signature and claims should be validated. Disabling validation is not recommended except for advanced or controlled environments.
   * @defaultValue true
   */
  validateIdToken?: boolean;

  /**
   * JSON Web Key Set used to validate the ID token signature.
   *
   * If not provided, the JWKS is automatically fetched from the authorization server metadata.
   */
  jwks?: Jwks;

  /**
   * Clock skew adjustment (in seconds) applied when validating ID token timestamps against the authorization server.
   */
  idTokenClockSkew?: number;

  /**
   * Additional allowed clock tolerance (in seconds) when validating time-based ID token claims such as `exp`, `iat`, and `nbf`.
   */
  idTokenClockTolerance?: number;

  /**
   * Options applied to the refresh token grant request, such as requesting tokens for specific resources or scopes.
   */
  refreshGrantOptions?: RefreshGrantOptions;

  /**
   * List of ID token claims to remove before storing the session.
   */
  filteredIdTokenClaims?: string[];

  /**
   * When enabled, replaces the existing session user profile with a freshly constructed profile
   * derived from the latest ID token and/or UserInfo response.
   *
   * @defaultValue false
   */
  strictProfileSync?: boolean;

  /**
   * Callback invoked before a session is created or updated. Allows customization or enrichment of the session.
   */
  onSessionCreating?: OnSessionCreating;
}

/**
 * Options used when refetching user profile data from the UserInfo endpoint.
 *
 * @category Types
 */
export interface RefetchUserInfoOptions {
  /**
   * When enabled, replaces the existing session user profile with a new profile
   * constructed from the latest UserInfo response.
   *
   * @defaultValue false
   */
  strictProfileSync?: boolean;

  /**
   * Callback invoked before a session is created or updated. Allows customization or enrichment of the session.

   */
  onSessionCreating?: OnSessionCreating;
}

/**
 * Supported OAuth 2.0 client authentication methods.
 *
 * These methods define how a client authenticates itself when calling the authorization server token endpoint.
 *
 * @category Types (Enums)
 */
export type ClientAuthMethod =
  /**
   * Client credentials are sent using HTTP Basic authentication
   */
  | 'client_secret_basic'

  /**
   * Client credentials are included in the request body as form parameters.
   */
  | 'client_secret_post'

  /**
   * Client authenticates using a signed JWT created with the client secret.
   */
  | 'client_secret_jwt'

  /**
   * Client authenticates using a signed JWT created with a private key.
   */
  | 'private_key_jwt'

  /**
   * Client authenticates using a TLS client certificate issued by a trusted certificate authority.
   */
  | 'tls_client_auth'

  /**
   * Client authenticates using a self-signed TLS client certificate.
   */
  | 'self_signed_tls_client_auth'

  /**
   * Client authenticates using a SPIFFE JWT-SVID sent as a JWT client assertion.
   */
  | 'spiffe_jwt'

  /**
   * Client authenticates using a SPIFFE X.509-SVID via mutual TLS.
   */
  | 'spiffe_x509';

/**
 * Parameters used when creating a Pushed Authorization Request (PAR).
 *
 * This type mirrors {@link AuthorizationParams} but excludes `requestUri`,
 * since the `request_uri` value is generated by the authorization server
 * after a successful PAR request and must not be supplied by the client.
 *
 * @category Types
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface PushedAuthorizationParams extends Omit<
  AuthorizationParams,
  'requestUri'
> {}

/**
 * Shared configuration options for MonoCloud OIDC clients.
 *
 * These options are common to both {@link MonoCloudOidcClientOptions}
 * and {@link MonoCloudOidcBackendClientOptions}.
 *
 * @category Types
 */
export interface MonoCloudClientOptionsBase {
  /**
   * Client secret or key material used for client authentication.
   *
   * When `clientAuthMethod` is `client_secret_jwt` and a plain-text secret is provided, the default signing algorithm is `HS256`.
   *
   * To use a different algorithm, provide a symmetric JSON Web Key (JWK) (`kty: "oct"`) with the desired algorithm specified in its `alg` property.
   *
   * When `clientAuthMethod` is `spiffe_jwt`, provide the SPIFFE JWT-SVID (obtained from the SPIFFE Workload API) as the plain-text string; it is sent as the `client_assertion`.
   */
  clientSecret?: string | Jwk;

  /**
   * Client authentication method used when communicating with the token endpoint.
   * @defaultValue 'client_secret_basic'
   */
  clientAuthMethod?: ClientAuthMethod;

  /**
   * Duration (in seconds) to cache the JSON Web Key Set (JWKS) retrieved from the authorization server.
   * @defaultValue 300
   */
  jwksCacheDuration?: number;

  /**
   * Duration (in seconds) to cache OpenID Connect discovery metadata.
   * @defaultValue 300
   */
  metadataCacheDuration?: number;

  /**
   * Optional custom `fetch` implementation used for network requests.
   */
  fetcher?: typeof fetch;
}

/**
 * Configuration options used to initialize the MonoCloudOidcClient.
 *
 * @category Types
 */
export interface MonoCloudOidcClientOptions extends MonoCloudClientOptionsBase {
  /**
   * Expected signing algorithm for validating ID tokens.
   * @defaultValue 'RS256'
   */
  idTokenSigningAlgorithm?: SecurityAlgorithms;
}

/**
 * Options for configuring group membership validation on access tokens.
 *
 * @category Types
 */
export interface IsUserInGroupOptions {
  /**
   * The claim name in the token that contains group memberships.
   * @defaultValue 'groups'
   */
  groupsClaim?: string;

  /**
   * When `true`, requires the token to contain all specified groups.
   * When `false`, requires at least one of the specified groups.
   * @defaultValue false
   */
  matchAll?: boolean;
}

/**
 * Configuration options used to initialize the MonoCloudOidcBackendClient.
 *
 * @category Types
 */
export interface MonoCloudOidcBackendClientOptions extends MonoCloudClientOptionsBase {
  /**
   * Client identifier of the application registered in MonoCloud.
   */
  clientId?: string;

  /**
   * Number of seconds to adjust the current time to account for clock differences.
   * @defaultValue 0
   */
  clockSkew?: number;

  /**
   * Additional time tolerance in seconds for time-based claim validation.
   * @defaultValue 300
   */
  clockTolerance?: number;

  /**
   * Options for group membership validation applied to all token validations performed by this client.
   */
  groupOptions?: IsUserInGroupOptions;
}

/**
 * Response returned from the Pushed Authorization Request (PAR) endpoint.
 *
 * @category Types
 */
export interface ParResponse {
  /**
   * The URI reference identifying the pushed authorization request.
   *
   * This value must be supplied as the `request_uri` parameter when redirecting the user to the authorization endpoint.
   */
  request_uri: string;

  /**
   * Lifetime of the `request_uri`, in seconds. After this duration expires, the authorization request becomes invalid.
   */
  expires_in: number;
}

/**
 * Callback invoked before a session is created or updated.
 *
 * This hook allows you to inspect or modify the session during the authentication lifecycle — for example, to enrich the session with custom claims, normalize user data, or apply application-specific logic.
 *
 * @category Types (Handler)
 *
 * @param session - The session being created or updated.
 * @param idToken - Optional. Claims extracted from the ID token.
 * @param userInfo - Optional. Claims returned from the `UserInfo` endpoint.
 * @returns Returns a promise or void. Execution continues once the callback completes.
 */
export type OnSessionCreating = (
  /**
   * The session being created or updated.
   */
  session: MonoCloudSession,

  /**
   * Optional. Claims extracted from the ID token received during authentication.
   */
  idToken?: Partial<IdTokenClaims>,

  /**
   * Optional. Claims returned from the UserInfo endpoint.
   */
  userInfo?: UserinfoResponse
) => Promise<void> | void;

/**
 * Shared options for token validation and introspection.
 * @category Types
 */
export interface TokenValidationOptionsBase {
  /**
   * List of scopes that must all be present in the token's `scope` claim.
   */
  scopes?: string[];

  /**
   * List of group names or identifiers that must be present in the token's groups claim.
   */
  groups?: string[];

  /**
   * PEM-encoded client certificate used for certificate-bound token validation.
   */
  clientCertificate?: string;

  /**
   * When `true`, validates certificate binding for certificate-bound access tokens.
   *
   * @defaultValue false
   */
  validateCertificateBinding?: boolean;
}

/**
 * Options for validating a JWT access token.
 *
 * @category Types
 */
export interface ValidateJwtAccessTokenOptions extends TokenValidationOptionsBase {
  /**
   * Pre-fetched JSON Web Key Set to use for signature verification instead of fetching from the server.
   */
  jwks?: Jwks;
}

/**
 * Options for introspecting an opaque access token.
 *
 * @category Types
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface IntrospectOptions extends TokenValidationOptionsBase {}
