import {
  decodeBase64Url,
  getPublicSigKeyFromIssuerJwks,
  keyToSubtle,
  now,
  stringToArrayBuffer,
} from './utils/internal';
import { clientAuth } from './client-auth';
import {
  AccessTokenClaims,
  ClientAuthMethod,
  IssuerMetadata,
  Jwk,
  Jwks,
  JwsHeaderParameters,
  MonoCloudApiClientOptions,
} from './types';
import { MonoCloudApiHttpError } from './errors/monocloud-api-http-error';
import { MonoCloudApiValidationError } from './errors/monocloud-api-validation-error';
import { MonoCloudApiTokenError } from './errors/monocloud-api-token-error';
import { MonoCloudApiOPError } from './errors/monocloud-api-op-error';

function assertMetadataProperty<K extends keyof IssuerMetadata>(
  metadata: IssuerMetadata,
  property: K
): asserts metadata is IssuerMetadata & Required<Pick<IssuerMetadata, K>> {
  if (metadata[property] === undefined || metadata[property] === null) {
    throw new MonoCloudApiValidationError(
      `${property as string} endpoint is required but not available in the issuer metadata`
    );
  }
}

const innerFetch = async (
  input: string,
  reqInit: RequestInit = {}
): Promise<Response> => {
  try {
    return await fetch(input, reqInit);
  } catch (e) {
    /* v8 ignore next -- @preserve */
    throw new MonoCloudApiHttpError(
      (e as any).message ?? 'Unexpected Network Error'
    );
  }
};

const deserializeJson = async <T = any>(res: Response): Promise<T> => {
  try {
    return await res.json();
  } catch (e) {
    throw new MonoCloudApiHttpError(
      /* v8 ignore next -- @preserve */
      `Failed to parse response body as JSON ${(e as any).message ? `: ${(e as any).message}` : ''}`
    );
  }
};

/**
 * Client for validating access tokens issued by a MonoCloud authorization server.
 *
 * Supports validation of both JWT and opaque access tokens. JWT tokens are validated
 * locally using the authorization server's published JWKS. Opaque tokens are validated
 * by calling the OAuth 2.0 Token Introspection endpoint (RFC 7662).
 *
 * @example
 * ```typescript
 * const client = new MonoCloudApiClient('example.monocloud.com', 'my-client-id', {
 *   clientSecret: 'my-client-secret',
 *   audience: 'https://api.example.com',
 * });
 *
 * const claims = await client.validateAccessToken(accessToken);
 * ```
 *
 * @category Classes
 */
export class MonoCloudApiClient {
  private readonly tenantDomain: string;

  private readonly clientId: string;

  private readonly clientSecret: string | Jwk;

  private readonly audience: string;

  private readonly authMethod: ClientAuthMethod;

  private jwks?: Jwks;

  private jwksCacheExpiry = 0;

  private jwksCacheDuration = 300;

  private metadata?: IssuerMetadata;

  private metadataCacheExpiry = 0;

  private metadataCacheDuration = 300;

  constructor(
    tenantDomain: string,
    clientId: string,
    options: MonoCloudApiClientOptions
  ) {
    // eslint-disable-next-line no-param-reassign
    tenantDomain ??= '';
    /* v8 ignore next -- @preserve */
    this.tenantDomain = `${!tenantDomain.startsWith('https://') ? 'https://' : ''}${tenantDomain.endsWith('/') ? tenantDomain.slice(0, -1) : tenantDomain}`;
    this.clientId = clientId;
    this.clientSecret = options.clientSecret;
    this.audience = options.audience;
    this.authMethod = options.clientAuthMethod ?? 'client_secret_post';

    if (options.jwksCacheDuration) {
      this.jwksCacheDuration = options.jwksCacheDuration;
    }

    if (options.metadataCacheDuration) {
      this.metadataCacheDuration = options.metadataCacheDuration;
    }
  }

  /**
   * Validates an access token and returns the token claims.
   *
   * Automatically detects whether the token is a JWT or an opaque token.
   * JWT tokens are validated locally by verifying the signature against the authorization server's JWKS.
   * Opaque tokens are validated by calling the OAuth 2.0 Token Introspection endpoint (RFC 7662).
   *
   * After obtaining the claims from either method, the following standard claims are validated:
   * - `iss` (issuer) must match the configured tenant domain
   * - `aud` (audience) must include the configured audience
   * - `exp` (expiration) must not be expired
   * - `nbf` (not before) must not be in the future
   *
   * @param accessToken - The access token string to validate.
   *
   * @returns The validated access token claims.
   *
   * @throws {@link MonoCloudApiValidationError} - When the access token is empty or invalid.
   *
   * @throws {@link MonoCloudApiTokenError} - When token validation fails (invalid signature, expired, wrong issuer/audience, etc.).
   *
   * @throws {@link MonoCloudApiOPError} - When the introspection endpoint returns a standardized OAuth 2.0 error response.
   *
   * @throws {@link MonoCloudApiHttpError} - When there is a network error or unexpected status code during the request.
   *
   */
  async validateAccessToken(accessToken: string): Promise<AccessTokenClaims> {
    if (typeof accessToken !== 'string' || !accessToken.trim().length) {
      throw new MonoCloudApiValidationError(
        'Access token is required for validation'
      );
    }

    const parts = accessToken.split('.');
    const isJwt = parts.length === 3;

    const claims = isJwt
      ? await this.validateJwt(accessToken)
      : await this.validateOpaqueToken(accessToken);

    const current = now();

    if (claims.iss !== undefined) {
      if (claims.iss !== this.tenantDomain) {
        throw new MonoCloudApiTokenError('Invalid Issuer');
      }
    }

    if (claims.aud !== undefined) {
      const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];

      if (!audience.includes(this.audience)) {
        throw new MonoCloudApiTokenError('Invalid audience claim');
      }
    }

    if (claims.exp !== undefined) {
      if (typeof claims.exp !== 'number') {
        throw new MonoCloudApiTokenError(
          'Unexpected "exp" (expiration time) claim type'
        );
      }

      if (claims.exp <= current) {
        throw new MonoCloudApiTokenError(
          'Unexpected "exp" (expiration time) claim value, timestamp is <= now()'
        );
      }
    }

    if (claims.nbf !== undefined) {
      if (typeof claims.nbf !== 'number') {
        throw new MonoCloudApiTokenError(
          'Unexpected "nbf" (not before) claim type'
        );
      }

      if (claims.nbf > current) {
        throw new MonoCloudApiTokenError(
          'Unexpected "nbf" (not before) claim value, timestamp is > now()'
        );
      }
    }

    return claims;
  }

  /**
   * Fetches the authorization server metadata from the .well-known endpoint.
   * The metadata is cached for the configured duration.
   *
   * @param forceRefresh - If `true`, bypasses the cache and fetches fresh metadata from the server.
   *
   * @returns The issuer metadata for the tenant, retrieved from the OpenID Connect discovery endpoint.
   *
   * @throws {@link MonoCloudApiHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async getMetadata(forceRefresh = false): Promise<IssuerMetadata> {
    if (!forceRefresh && this.metadata && this.metadataCacheExpiry > now()) {
      return this.metadata;
    }

    this.metadata = undefined;

    const response = await innerFetch(
      `${this.tenantDomain}/.well-known/openid-configuration`
    );

    if (response.status !== 200) {
      throw new MonoCloudApiHttpError(
        `Error while fetching metadata. Unexpected status code: ${response.status}`
      );
    }

    const metadata = await deserializeJson<IssuerMetadata>(response);

    this.metadata = metadata;
    this.metadataCacheExpiry = now() + this.metadataCacheDuration;

    return metadata;
  }

  /**
   * Fetches the JSON Web Keys used to verify access token signatures.
   * The JWKS is cached for the configured duration.
   *
   * @param forceRefresh - If `true`, bypasses the cache and fetches fresh set of JWKS from the server.
   *
   * @returns The JSON Web Key Set containing the public keys for token verification.
   *
   * @throws {@link MonoCloudApiHttpError} - Thrown if there is a network error during the request or
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

    const response = await innerFetch(metadata.jwks_uri);

    if (response.status !== 200) {
      throw new MonoCloudApiHttpError(
        `Error while fetching JWKS. Unexpected status code: ${response.status}`
      );
    }
    const jwks = await deserializeJson<Jwks>(response);

    this.jwks = jwks;
    this.jwksCacheExpiry = now() + this.jwksCacheDuration;

    return jwks;
  }

  private async validateJwt(accessToken: string): Promise<AccessTokenClaims> {
    const {
      0: protectedHeader,
      1: payload,
      2: encodedSignature,
      length,
    } = accessToken.split('.');

    if (length !== 3) {
      throw new MonoCloudApiTokenError(
        'Access token must have a header, payload and signature'
      );
    }

    let header: JwsHeaderParameters;
    try {
      header = JSON.parse(decodeBase64Url(protectedHeader));
    } catch {
      throw new MonoCloudApiTokenError('Failed to parse JWT Header');
    }

    if (
      header === null ||
      typeof header !== 'object' ||
      Array.isArray(header)
    ) {
      throw new MonoCloudApiTokenError('JWT Header must be a top level object');
    }

    if (header.crit !== undefined) {
      throw new MonoCloudApiTokenError(
        'Unexpected JWT "crit" header parameter'
      );
    }

    const binary = decodeBase64Url(encodedSignature);

    const signature = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
      signature[i] = binary.charCodeAt(i);
    }

    const jwks = await this.getJwks();

    const key = await getPublicSigKeyFromIssuerJwks(jwks.keys, header);

    const input = `${protectedHeader}.${payload}`;

    const verified = await crypto.subtle.verify(
      keyToSubtle(key),
      key,
      signature,
      stringToArrayBuffer(input) as BufferSource
    );

    if (!verified) {
      throw new MonoCloudApiTokenError('JWT signature verification failed');
    }

    let claims: AccessTokenClaims;

    try {
      claims = JSON.parse(decodeBase64Url(payload));
    } catch {
      throw new MonoCloudApiTokenError('Failed to parse JWT Payload');
    }

    if (
      claims === null ||
      typeof claims !== 'object' ||
      Array.isArray(claims)
    ) {
      throw new MonoCloudApiTokenError(
        'JWT Payload must be a top level object'
      );
    }

    return claims;
  }

  private async validateOpaqueToken(
    accessToken: string
  ): Promise<AccessTokenClaims> {
    const metadata = await this.getMetadata();

    assertMetadataProperty(metadata, 'introspection_endpoint');

    const body = new URLSearchParams();
    body.set('token', accessToken);

    const headers: Record<string, string> = {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    };

    clientAuth(
      this.clientId,
      this.clientSecret,
      this.authMethod,
      this.tenantDomain,
      headers,
      body
    );

    const response = await innerFetch(metadata.introspection_endpoint, {
      method: 'POST',
      body: body.toString(),
      headers,
    });

    if (response.status === 400) {
      const standardBodyError = await deserializeJson(response);

      throw new MonoCloudApiOPError(
        standardBodyError.error ?? 'introspection_failed',
        standardBodyError.error_description ?? 'Token introspection failed'
      );
    }

    if (response.status === 401) {
      throw new MonoCloudApiHttpError(
        'Client authentication failed at the introspection endpoint'
      );
    }

    if (response.status !== 200) {
      throw new MonoCloudApiHttpError(
        `Error while performing token introspection. Unexpected status code: ${response.status}`
      );
    }

    const introspectionResponse = await deserializeJson<
      AccessTokenClaims & { active?: boolean }
    >(response);

    if (!introspectionResponse.active) {
      throw new MonoCloudApiTokenError('Token is not active');
    }

    const { active: _, ...claims } = introspectionResponse;

    return claims;
  }
}
