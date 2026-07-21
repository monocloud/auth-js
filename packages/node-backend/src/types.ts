import {
  AccessTokenClaims,
  IntrospectOptions,
  MonoCloudOidcBackendClientOptions,
} from '@monocloud/auth-core';

/**
 * Callback that resolves a PEM-encoded client certificate from the incoming request.
 *
 * The returned certificate can include or omit the `-----BEGIN CERTIFICATE-----` /
 * `-----END CERTIFICATE-----` delimiters.
 *
 * @typeParam T - Type of the request
 *
 * @category Types (Handler)
 */
export type ClientCertificateResolver<T> = (
  /**
   * The incoming request object.
   */
  req: T
) => Promise<string | undefined>;

/**
 * Callback that resolves an access token from the incoming request.
 *
 * When provided, this takes precedence over the default `Authorization: Bearer` header extraction.
 *
 * @typeParam T - Type of the request
 *
 * @category Types (Handler)
 */
export type TokenResolver<T> = (
  /**
   * The incoming request object.
   */
  req: T
) => Promise<string | undefined>;

/**
 * Options for customizing how access tokens and client certificates are extracted from incoming requests.
 *
 * @typeParam T - Type of the request
 *
 * @category Types
 */
export interface ProtectApiRequestOptions<T> {
  /**
   * Custom callback to resolve the PEM-encoded client certificate from the request.
   */
  certificateResolver?: ClientCertificateResolver<T>;
  /**
   * Custom callback to extract the access token from the request.
   * When provided, overrides the default `Authorization: Bearer` header extraction.
   */
  tokenResolver?: TokenResolver<T>;
}

/**
 * Configuration options for the {@link MonoCloudBackendNodeClient}.
 *
 * ## Configuration Sources
 *
 * Configuration values can be provided using either:
 *
 * - **Constructor options** - passed when creating the client instance.
 * - **Environment variables** - using `MONOCLOUD_BACKEND_*` variables.
 *
 * When both are provided, **constructor options override environment variables**.
 *
 * ## Environment Variables
 *
 * ### Core Configuration (Required)
 *
 * | Environment Variable | Description |
 * |----------------------|-------------|
 * | `MONOCLOUD_BACKEND_TENANT_DOMAIN` | The domain of your MonoCloud tenant (for example, `https://your-tenant.us.monocloud.com`). |
 * | `MONOCLOUD_BACKEND_AUDIENCE` | The expected audience for access token validation (for example, `https://api.example.com`). |
 *
 * ### Introspection
 *
 * | Environment Variable | Description |
 * |----------------------|-------------|
 * | `MONOCLOUD_BACKEND_CLIENT_ID` | Unique identifier for your application/client. |
 * | `MONOCLOUD_BACKEND_CLIENT_SECRET` | Application/client secret used for authentication. When `clientAuthMethod` is `private_key_jwt`, provide the private key JWK as a JSON string (it is parsed automatically). |
 * | `MONOCLOUD_BACKEND_CLIENT_AUTH_METHOD` | Client authentication method (for example, `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth`, `spiffe_jwt`, `spiffe_x509`). |
 *
 * ### mTLS
 *
 * | Environment Variable | Description |
 * |----------------------|-------------|
 * | `MONOCLOUD_BACKEND_TRUST_STORE_ID` | Identifier of the trust store whose mTLS endpoint aliases (`mtls_additional_endpoint_aliases`) should be used when authenticating with a mutual-TLS client authentication method. When omitted, the default `mtls_endpoint_aliases` are used. |
 *
 * ### Token Validation
 *
 * | Environment Variable | Description |
 * |----------------------|-------------|
 * | `MONOCLOUD_BACKEND_CLOCK_SKEW` | Allowed clock drift (in seconds) when validating token timestamps. |
 * | `MONOCLOUD_BACKEND_CLOCK_TOLERANCE` | Additional time tolerance (in seconds) for time-based claim validation. |
 * | `MONOCLOUD_BACKEND_INTROSPECT_JWT_TOKENS` | When `true`, JWT tokens are introspected at the server instead of being validated locally. |
 *
 * ### Group Validation
 *
 * | Environment Variable | Description |
 * |----------------------|-------------|
 * | `MONOCLOUD_BACKEND_GROUPS_CLAIM` | The claim name in the token that contains group memberships. |
 * | `MONOCLOUD_BACKEND_GROUPS_MATCH_ALL` | When `true`, requires the token to contain all specified groups. |
 *
 * ### Caching
 *
 * | Environment Variable | Description |
 * |----------------------|-------------|
 * | `MONOCLOUD_BACKEND_JWKS_CACHE_DURATION` | Duration (in seconds) to cache the JSON Web Key Set (JWKS) used to verify tokens. |
 * | `MONOCLOUD_BACKEND_METADATA_CACHE_DURATION` | Duration (in seconds) to cache the OpenID Connect discovery metadata. |
 *
 * @category Types
 */
export interface MonoCloudBackendNodeClientOptions extends MonoCloudOidcBackendClientOptions {
  /**
   * The MonoCloud tenant domain URL (e.g. `https://example.monocloud.dev`).
   */
  tenantDomain: string;
  /**
   * The expected audience URI for access token validation (e.g. `https://api.example.com`).
   */
  audience: string;
  /**
   * Optional cache for access token introspection results. Only tokens validated via
   * introspection are cached (opaque tokens, and JWTs when `introspectJwtTokens` is `true`);
   * locally-validated JWTs are not cached.
   */
  cache?: IIntrospectionCache;
  /**
   * When `true`, JWT access tokens are introspected instead of locally validated.
   *
   * This skips JWT signature/header/payload checks and always uses the introspection endpoint.
   *
   * @defaultValue false
   */
  introspectJwtTokens?: boolean;
}

/**
 * Cache adapter for storing access token introspection results.
 *
 * Implement this interface to persist introspection results in an external store such as
 * Redis, Memcached, or an in-memory cache.
 *
 * @category Types
 */
export interface IIntrospectionCache {
  /**
   * Stores introspected access token claims in the cache.
   *
   * @param key - The cache key (access token).
   * @param claims - The introspected access token claims to cache.
   * @param expiresAt - The token's expiration time as a Unix epoch timestamp (seconds).
   */
  set(key: string, claims: AccessTokenClaims, expiresAt: number): Promise<void>;
  /**
   * Retrieves cached claims by key.
   *
   * @param key - The cache key.
   * @returns The cached claims, or `null`/`undefined` if the entry does not exist or has expired.
   */
  get(key: string): Promise<AccessTokenClaims | null | undefined>;
  /**
   * Removes an entry from the cache.
   *
   * @param key - The cache key to delete.
   */
  delete(key: string): Promise<void>;
}

/**
 * Options for validating access tokens.
 *
 * @category Types
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface ValidateAccessTokenOptions extends IntrospectOptions {}

/**
 * Options for protecting APIs.
 *
 * @category Types
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface ProtectOptions extends Omit<
  ValidateAccessTokenOptions,
  'clientCertificate'
> {}
