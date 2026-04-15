import { decodeBase64Url, now } from './utils/internal';
import { JwtClaims, IssuerMetadata, Jwks } from './types';
import { MonoCloudHttpError } from './errors/monocloud-http-error';
import { MonoCloudTokenError } from './errors/monocloud-token-error';
import { MonoCloudAuthBaseError } from './errors/monocloud-auth-base-error';
import { assertMetadataProperty, deserializeJson, innerFetch } from './helper';

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
   * Creates a new instance of MonoCloudOidcClientBase.
   *
   * @param tenantDomain - The tenant domain URL.
   * @param metadataCacheDuration - Duration (in seconds) to cache OpenID Connect discovery metadata. Defaults to 300 (5 minutes).
   * @param jwksCacheDuration - Duration (in seconds) to cache the JSON Web Key Set (JWKS). Defaults to 300 (5 minutes).
   * @param fetcher - Custom `fetch` implementation used for making HTTP requests. Falls back to the global `fetch` if not provided.
   */
  constructor(
    tenantDomain: string,
    metadataCacheDuration?: number,
    jwksCacheDuration?: number,
    fetcher?: typeof fetch
  ) {
    // eslint-disable-next-line no-param-reassign
    tenantDomain ??= '';
    /* v8 ignore next -- @preserve */
    this.tenantDomain = `${!tenantDomain.startsWith('https://') ? 'https://' : ''}${tenantDomain.endsWith('/') ? tenantDomain.slice(0, -1) : tenantDomain}`;

    if (metadataCacheDuration !== undefined) {
      this.metadataCacheDuration = metadataCacheDuration;
    }

    if (jwksCacheDuration !== undefined) {
      this.jwksCacheDuration = jwksCacheDuration;
    }

    this.fetcher = fetcher;
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

    this.metadata = undefined;

    const response = await innerFetch(
      `${this.tenantDomain}/.well-known/openid-configuration`,
      undefined,
      this.fetcher
    );

    if (response.status !== 200) {
      throw new MonoCloudHttpError(
        `Error while fetching metadata. Unexpected status code: ${response.status}`
      );
    }

    const metadata = await deserializeJson<IssuerMetadata>(response);

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

    this.jwks = undefined;

    const metadata = await this.getMetadata();

    assertMetadataProperty(metadata, 'jwks_uri');

    const response = await innerFetch(
      metadata.jwks_uri,
      undefined,
      this.fetcher
    );

    if (response.status !== 200) {
      throw new MonoCloudHttpError(
        `Error while fetching JWKS. Unexpected status code: ${response.status}`
      );
    }
    const jwks = await deserializeJson<Jwks>(response);

    this.jwks = jwks;
    this.jwksCacheExpiry = now() + this.jwksCacheDuration;

    return jwks;
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
