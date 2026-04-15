import {
  AccessTokenClaims,
  MonoCloudOidcBackendClient,
  MonoCloudValidationError,
} from '@monocloud/auth-core';
import {
  ICache,
  MonoCloudBackendNodeClientOptions,
  ValidateAccessTokenOptions,
} from './types';
import { now, sha256 } from '@monocloud/auth-core/internal';
import { getOptions } from './options/get-options';

/**
 * Backend client for validating access tokens in Node.js server applications.
 *
 * Extends the core OIDC backend client with caching support and automatic
 * detection of JWT vs. opaque token formats.
 *
 * @category Classes
 */
export class MonoCloudBackendNodeClient extends MonoCloudOidcBackendClient {
  private readonly cache: ICache | undefined;

  private readonly introspectJwtToken: boolean | undefined;

  /**
   * Creates a new instance of MonoCloudBackendNodeClient.
   *
   * @param options - Client configuration options. When omitted, configuration is read from environment variables.
   */
  constructor(options?: Partial<MonoCloudBackendNodeClientOptions>) {
    const validatedOptions = getOptions(options);
    super(validatedOptions.tenantDomain, validatedOptions.audience, {
      clientId: validatedOptions.clientId,
      clientSecret: validatedOptions.clientSecret,
      clientAuthMethod: validatedOptions.clientAuthMethod,
      groupOptions: validatedOptions.groupOptions,
      clockSkew: validatedOptions.clockSkew,
      clockTolerance: validatedOptions.clockTolerance,
      fetcher: validatedOptions.fetcher,
      jwksCacheDuration: validatedOptions.jwksCacheDuration,
      metadataCacheDuration: validatedOptions.metadataCacheDuration,
    });

    this.introspectJwtToken = validatedOptions?.introspectJwtTokens;

    if (validatedOptions.cache) {
      this.cache = validatedOptions.cache;
    }
  }

  /**
   * Validates an access token by automatically detecting its format.
   *
   * @param accessToken - The access token string to validate.
   * @param options - Validation options.
   *
   * @returns Validated access token claims.
   *
   * @throws {@link MonoCloudValidationError} - When the access token is empty.
   *
   * @throws {@link MonoCloudTokenError} - If token validation fails.
   *
   * @throws {@link MonoCloudOPError} - When the introspection endpoint returns a standardized
   * OAuth 2.0 error response.
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async validateAccessToken(
    accessToken: string,
    options?: ValidateAccessTokenOptions
  ): Promise<AccessTokenClaims> {
    if (typeof accessToken !== 'string' || accessToken.trim().length === 0) {
      throw new MonoCloudValidationError(
        'Access token must be a valid non-empty string'
      );
    }

    const cacheKey = this.cache ? await sha256(accessToken) : undefined;

    if (this.cache && cacheKey) {
      const cached = await this.cache.get(cacheKey);
      if (
        cached &&
        typeof cached.exp === 'number' &&
        cached.exp > now() + this.clockSkew - this.clockTolerance
      ) {
        return cached;
      }
    }

    let claims: AccessTokenClaims;

    if (accessToken.split('.').length === 3 && !this.introspectJwtToken) {
      claims = await this.validateJwtAccessToken(accessToken, {
        scopes: options?.scopes,
        groups: options?.groups,
        validateCertificateBinding: options?.validateCertificateBinding,
        clientCertificate: options?.clientCertificate,
      });
    } else {
      claims = await this.introspectAccessToken(accessToken, {
        scopes: options?.scopes,
        groups: options?.groups,
        validateCertificateBinding: options?.validateCertificateBinding,
        clientCertificate: options?.clientCertificate,
      });
    }

    if (this.cache && cacheKey && typeof claims.exp === 'number') {
      await this.cache.set(cacheKey, claims, claims.exp);
    }

    return claims;
  }
}
