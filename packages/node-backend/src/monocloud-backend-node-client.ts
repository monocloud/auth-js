import {
  AccessTokenClaims,
  MonoCloudOidcBackendClient,
  MonoCloudValidationError,
} from '@monocloud/auth-core';
import {
  IIntrospectionCache,
  MonoCloudBackendNodeClientOptions,
  ValidateAccessTokenOptions,
} from './types';
import { isPresent, now } from '@monocloud/auth-core/internal';
import { getOptions } from './options/get-options';

/**
 * Backend client for validating access tokens in Node.js server applications.
 *
 * Extends the core OIDC backend client with introspection caching and
 * automatic detection of JWT vs. opaque token formats.
 *
 * @category Classes
 */
export class MonoCloudBackendNodeClient extends MonoCloudOidcBackendClient {
  private readonly cache: IIntrospectionCache | undefined;

  private readonly introspectJwtToken: boolean | undefined;

  private readonly introspectionConfigured: boolean;

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
      trustStoreId: validatedOptions.trustStoreId,
      metadataResolver: validatedOptions.metadataResolver,
      jwksResolver: validatedOptions.jwksResolver,
      groupOptions: validatedOptions.groupOptions,
      clockSkew: validatedOptions.clockSkew,
      clockTolerance: validatedOptions.clockTolerance,
      fetcher: validatedOptions.fetcher,
      responseTimeout: validatedOptions.responseTimeout,
      jwksCacheDuration: validatedOptions.jwksCacheDuration,
      metadataCacheDuration: validatedOptions.metadataCacheDuration,
    });

    this.introspectJwtToken = validatedOptions?.introspectJwtTokens;
    this.introspectionConfigured = isPresent(validatedOptions.clientId);

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
   * @throws {@link MonoCloudValidationError} - When the access token is empty, or when the
   * token must be introspected and no introspection credentials are configured.
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

    let claims: AccessTokenClaims;

    if (accessToken.split('.').length === 3 && !this.introspectJwtToken) {
      claims = await this.validateJwtAccessToken(accessToken, {
        scopes: options?.scopes,
        groups: options?.groups,
        validateCertificateBinding: options?.validateCertificateBinding,
        clientCertificate: options?.clientCertificate,
      });
    } else {
      if (!this.introspectionConfigured) {
        throw new MonoCloudValidationError(
          'Token introspection is not configured'
        );
      }

      if (this.cache) {
        const cached = await this.cache.get(accessToken);
        if (
          cached &&
          typeof cached.exp === 'number' &&
          cached.exp > now() + this.clockSkew - this.clockTolerance
        ) {
          this.validateAccessTokenClaims(
            cached,
            options?.scopes,
            options?.groups
          );

          if (options?.validateCertificateBinding) {
            await this.validateCertificateBinding(
              cached,
              options.clientCertificate
            );
          }

          return cached;
        }
      }

      claims = await this.introspectAccessToken(accessToken, {
        scopes: options?.scopes,
        groups: options?.groups,
        validateCertificateBinding: options?.validateCertificateBinding,
        clientCertificate: options?.clientCertificate,
      });

      if (this.cache && typeof claims.exp === 'number') {
        await this.cache.set(accessToken, claims, claims.exp);
      }
    }

    return claims;
  }
}
