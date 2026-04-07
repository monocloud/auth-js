/**
 * Supported client authentication methods for the MonoCloud API client.
 *
 * These methods define how a client authenticates itself when calling the authorization server's introspection endpoint.
 *
 * @category Types (Enums)
 */
export type ClientAuthMethod =
  /**
   * Client credentials are sent using HTTP Basic authentication.
   */
  | 'client_secret_basic'

  /**
   * Client credentials are sent as form parameters in the request body.
   */
  | 'client_secret_post'

  /**
   * Client authenticates using a signed JWT created with the client secret.
   */
  | 'client_secret_jwt'

  /**
   * Client authenticates using a signed JWT created with a private key.
   */
  | 'private_key_jwt';

/**
 * Supported digital signature algorithms for verifying JSON Web Tokens.
 *
 * @category Types (Enums)
 */
export type SecurityAlgorithms =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES384'
  | 'ES512';

/**
 * Represents a JSON Web Key (JWK) used for cryptographic operations such as signing and verification.
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
 * Represents the protected header parameters of a JSON Web Signature (JWS).
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
 * Represents the OpenID Connect discovery metadata returned by the authorization server.
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
   * Supported token endpoint authentication methods.
   */
  token_endpoint_auth_methods_supported: string[];

  /**
   * Supported ID token signing algorithms.
   */
  id_token_signing_alg_values_supported: string[];

  /**
   * Supported subject identifier types.
   */
  subject_types_supported: string[];

  /**
   * Supported code challenge methods for PKCE.
   */
  code_challenge_methods_supported: string[];

  /**
   * Indicates support for the `request` parameter.
   */
  request_parameter_supported: boolean;

  /**
   * Indicates support for `request_uri` parameter.
   */
  request_uri_parameter_supported: boolean;

  /**
   * Supported request object signing algorithms.
   */
  request_object_signing_alg_values_supported: string[];

  /**
   * Indicates whether pushed authorization requests are required.
   */
  require_pushed_authorization_requests: boolean;
}

/**
 * Represents the claims contained in a validated access token.
 *
 * Includes standard JWT claims as well as any additional custom claims present in the token.
 *
 * @category Types
 */
export interface AccessTokenClaims {
  /**
   * Issuer of the token.
   */
  iss?: string;

  /**
   * Subject (user identifier) of the token.
   */
  sub?: string;

  /**
   * Audience the token is intended for.
   */
  aud?: string | string[];

  /**
   * Expiration time (Unix timestamp in seconds).
   */
  exp?: number;

  /**
   * Not-before time (Unix timestamp in seconds).
   */
  nbf?: number;

  /**
   * Issued-at time (Unix timestamp in seconds).
   */
  iat?: number;

  /**
   * JWT ID (unique identifier for the token).
   */
  jti?: string;

  /**
   * OAuth scope associated with the token.
   */
  scope?: string;

  /**
   * Client ID of the application the token was issued to.
   */
  client_id?: string;

  /**
   * Additional claims present in the token.
   */
  [key: string]: unknown;
}

/**
 * Configuration options used to initialize the MonoCloudApiClient.
 *
 * @category Types
 */
export interface MonoCloudApiClientOptions {
  /**
   * Client secret used for client authentication with the introspection endpoint.
   */
  clientSecret: string | Jwk;

  /**
   * The expected audience value for validating access tokens.
   */
  audience: string;

  /**
   * Client authentication method used when communicating with the introspection endpoint.
   * @defaultValue 'client_secret_post'
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
}
