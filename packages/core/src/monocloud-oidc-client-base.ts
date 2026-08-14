import { decodeBase64Url, now } from './utils/internal';
import {
  JwtClaims,
  IssuerMetadata,
  Jwks,
  MonoCloudOidcClientBaseOptions,
  MtlsEndpointAliases,
} from './types';
import { MonoCloudHttpError } from './errors/monocloud-http-error';
import { MonoCloudTokenError } from './errors/monocloud-token-error';
import { MonoCloudAuthBaseError } from './errors/monocloud-auth-base-error';
import { MonoCloudValidationError } from './errors/monocloud-validation-error';
import { isMtlsClientAuthMethod } from './client-auth';
import {
  assertMetadataProperty,
  deserializeJson,
  innerFetch,
  readRawResponse,
} from './helper';

/**
 * @category Classes
 */
export class MonoCloudOidcClientBase {
  /**
   * The normalized tenant domain URL used as the base for discovery endpoints.
   */
  protected readonly tenantDomain: string;

  /**
   * Cached JSON Web Key Set retrieved from the issuer's JWKS endpoint.
   */
  protected jwks?: Jwks;

  /**
   * Timestamp (in seconds) when the cached JWKS expires.
   */
  protected jwksCacheExpiry = 0;

  /**
   * Duration (in seconds) for which the JWKS is cached. Defaults to 300 (5 minutes).
   */
  protected jwksCacheDuration = 300;

  /**
   * Cached issuer metadata retrieved from the OpenID Connect discovery endpoint.
   */
  protected metadata?: IssuerMetadata;

  /**
   * Timestamp (in seconds) when the cached metadata expires.
   */
  protected metadataCacheExpiry = 0;

  /**
   * Duration (in seconds) for which the metadata is cached. Defaults to 300 (5 minutes).
   */
  protected metadataCacheDuration = 300;

  /**
   * Custom fetch implementation used for making HTTP requests. Falls back to the global `fetch` if not provided.
   */
  protected fetcher?: typeof fetch;

  /**
   * Identifier of the trust store whose mTLS endpoint aliases should be used, if any.
   */
  protected readonly trustStoreId?: string;

  /**
   * Optional custom resolver for the issuer metadata, used instead of the discovery request.
   */
  protected readonly metadataResolver?: () =>
    | IssuerMetadata
    | Promise<IssuerMetadata>;

  /**
   * Optional custom resolver for the JSON Web Key Set, used instead of the JWKS request.
   */
  protected readonly jwksResolver?: () => Jwks | Promise<Jwks>;

  /**
   * Whether the configured client authentication method uses mutual TLS, and therefore requires
   * the mTLS endpoint aliases from the issuer metadata.
   */
  protected readonly usesMtlsEndpoints: boolean;

  /**
   * Creates a new instance of MonoCloudOidcClientBase.
   *
   * @param options - Base client configuration options.
   */
  constructor(options: MonoCloudOidcClientBaseOptions) {
    let { tenantDomain } = options;
    tenantDomain ??= '';
    /* v8 ignore next -- @preserve */
    this.tenantDomain = `${!tenantDomain.startsWith('https://') ? 'https://' : ''}${tenantDomain.endsWith('/') ? tenantDomain.slice(0, -1) : tenantDomain}`;

    if (options.metadataCacheDuration !== undefined) {
      this.metadataCacheDuration = options.metadataCacheDuration;
    }

    if (options.jwksCacheDuration !== undefined) {
      this.jwksCacheDuration = options.jwksCacheDuration;
    }

    this.fetcher = options.fetcher;
    this.trustStoreId = options.trustStoreId;
    this.metadataResolver = options.metadataResolver;
    this.jwksResolver = options.jwksResolver;
    this.usesMtlsEndpoints = isMtlsClientAuthMethod(options.clientAuthMethod);
  }

  /**
   * Fetches the authorization server metadata from the .well-known endpoint.
   * The metadata is cached for 5 minutes by default.
   *
   * @param forceRefresh - If `true`, bypasses the cache and fetches fresh metadata from the server.
   *
   * @returns The issuer metadata for the tenant, retrieved from the OpenID Connect discovery endpoint.
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async getMetadata(forceRefresh = false): Promise<IssuerMetadata> {
    if (!forceRefresh && this.metadata && this.metadataCacheExpiry > now()) {
      return this.metadata;
    }

    let metadata: IssuerMetadata;

    if (this.metadataResolver) {
      metadata = await this.metadataResolver();
    } else {
      const response = await innerFetch(
        `${this.tenantDomain}/.well-known/openid-configuration`,
        undefined,
        this.fetcher
      );

      if (response.status !== 200) {
        const raw = await readRawResponse(response);

        throw new MonoCloudHttpError(
          `Error while fetching metadata. Unexpected status code: ${response.status}`,
          raw
        );
      }

      metadata = await deserializeJson<IssuerMetadata>(response);
    }

    this.metadata = metadata;
    this.metadataCacheExpiry = now() + this.metadataCacheDuration;

    return metadata;
  }

  /**
   * Fetches the JSON Web Keys used to sign the ID token.
   * The JWKS is cached for 5 minutes by default.
   *
   * @param forceRefresh - If `true`, bypasses the cache and fetches fresh set of JWKS from the server.
   *
   * @returns The JSON Web Key Set containing the public keys for token verification.
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async getJwks(forceRefresh = false): Promise<Jwks> {
    if (!forceRefresh && this.jwks && this.jwksCacheExpiry > now()) {
      return this.jwks;
    }

    let jwks: Jwks;

    if (this.jwksResolver) {
      jwks = await this.jwksResolver();
    } else {
      const metadata = await this.getMetadata();

      assertMetadataProperty(metadata, 'jwks_uri');

      const response = await innerFetch(
        metadata.jwks_uri,
        undefined,
        this.fetcher
      );

      if (response.status !== 200) {
        const raw = await readRawResponse(response);

        throw new MonoCloudHttpError(
          `Error while fetching JWKS. Unexpected status code: ${response.status}`,
          raw
        );
      }

      jwks = await deserializeJson<Jwks>(response);
    }

    this.jwks = jwks;
    this.jwksCacheExpiry = now() + this.jwksCacheDuration;

    return jwks;
  }

  /**
   * Resolves an endpoint URL from the issuer metadata, preferring the mutual-TLS alias when the
   * client authenticates over mTLS.
   *
   * @param metadata - The issuer metadata.
   * @param endpoint - The endpoint to resolve.
   *
   * @returns The resolved endpoint URL.
   *
   * @throws {@link MonoCloudValidationError} - When the required endpoint is not available in the issuer metadata.
   */
  protected resolveEndpoint(
    metadata: IssuerMetadata,
    endpoint: keyof MtlsEndpointAliases
  ): string {
    if (this.usesMtlsEndpoints) {
      const aliases = this.trustStoreId
        ? metadata.mtls_additional_endpoint_aliases?.[this.trustStoreId]
        : metadata.mtls_endpoint_aliases;

      const url = aliases?.[endpoint];

      if (typeof url !== 'string' || url.length === 0) {
        throw new MonoCloudValidationError(
          this.trustStoreId
            ? `mTLS ${endpoint} is required but not available for trust store '${this.trustStoreId}' in the issuer metadata`
            : `mTLS ${endpoint} is required but not available in the issuer metadata`
        );
      }

      return url;
    }

    assertMetadataProperty(metadata, endpoint);

    return metadata[endpoint];
  }

  /**
   * Decodes the payload of a JSON Web Token (JWT) and returns it as an object.
   *
   * >Note: THIS METHOD DOES NOT VERIFY JWT TOKENS.
   *
   * @param jwt - JWT to decode.
   *
   * @returns Decoded payload.
   *
   * @throws {@link MonoCloudTokenError} - If decoding fails
   *
   */
  static decodeJwt(jwt: string): JwtClaims {
    try {
      const [, payload] = jwt.split('.');

      if (!payload?.trim()) {
        throw new MonoCloudTokenError('JWT does not contain payload');
      }

      const decoded = decodeBase64Url(payload);

      if (!decoded.startsWith('{')) {
        throw new MonoCloudTokenError('Payload is not an object');
      }

      return JSON.parse(decoded) as JwtClaims;
    } catch (e) {
      if (e instanceof MonoCloudAuthBaseError) {
        throw e;
      }

      throw new MonoCloudTokenError(
        'Could not parse payload. Malformed payload'
      );
    }
  }
}
