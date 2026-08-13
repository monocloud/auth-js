import {
  arrayBufferToBase64,
  decodeBase64Url,
  getPublicSigKeyFromIssuerJwks,
  now,
  parseSpaceSeparated,
  stringToArrayBuffer,
  timingSafeEqual,
} from './utils/internal';
import { isUserInGroup } from './utils';
import { clientAuth, keyToSubtle } from './client-auth';
import {
  AccessTokenClaims,
  ClientAuthMethod,
  IntrospectOptions,
  IsUserInGroupOptions,
  Jwk,
  JwsHeaderParameters,
  ValidateJwtAccessTokenOptions,
  MonoCloudOidcBackendClientOptions,
} from './types';
import { MonoCloudOPError } from './errors/monocloud-op-error';
import { MonoCloudHttpError } from './errors/monocloud-http-error';
import { MonoCloudValidationError } from './errors/monocloud-validation-error';
import { MonoCloudTokenError } from './errors/monocloud-token-error';
import { MonoCloudOidcClientBase } from './monocloud-oidc-client-base';
import {
  deserializeJson,
  innerFetch,
  JWT_ASSERTION_CLOCK_SKEW,
} from './helper';

/**
 * @category Classes
 */
export class MonoCloudOidcBackendClient extends MonoCloudOidcClientBase {
  private readonly clientId?: string;

  private readonly clientSecret?: string | Jwk;

  private readonly authMethod: ClientAuthMethod;

  private readonly audience: string;

  private readonly groupOptions?: IsUserInGroupOptions;

  /**
   * Number of seconds to adjust the current time to account for clock differences between the client and server during time-based claim validation. Defaults to 0.
   */
  protected clockSkew = 0;

  /**
   * Additional time tolerance in seconds applied when validating time-based claims (`exp`, `nbf`). Defaults to 60 (1 minute).
   */
  protected clockTolerance = 60;

  /**
   * Creates a new instance of MonoCloudOidcBackendClient.
   *
   * @param tenantDomain - The tenant domain URL.
   * @param audience - The expected audience value used to validate the `aud` claim in access tokens.
   * @param options - Additional client configuration options.
   */
  constructor(
    tenantDomain: string,
    audience: string,
    options?: MonoCloudOidcBackendClientOptions
  ) {
    super({
      tenantDomain,
      metadataCacheDuration: options?.metadataCacheDuration,
      jwksCacheDuration: options?.jwksCacheDuration,
      fetcher: options?.fetcher,
      clientAuthMethod: options?.clientAuthMethod ?? 'client_secret_basic',
      trustStoreId: options?.trustStoreId,
      metadataResolver: options?.metadataResolver,
      jwksResolver: options?.jwksResolver,
    });
    this.audience = audience;

    if (options?.clientId) {
      this.clientId = options.clientId;
    }
    this.clientSecret = options?.clientSecret;
    this.authMethod = options?.clientAuthMethod ?? 'client_secret_basic';
    this.groupOptions = options?.groupOptions;

    if (options?.clockSkew !== undefined) {
      this.clockSkew = options.clockSkew;
    }

    if (options?.clockTolerance !== undefined) {
      this.clockTolerance = options.clockTolerance;
    }
  }

  /**
   * Validates an opaque access token using the OAuth 2.0 Token Introspection endpoint (RFC 7662).
   *
   * @param accessToken - The access token string to introspect.
   * @param options - Claims validation options.
   *
   * @returns Validated access token claims (without the `active` field).
   *
   * @throws {@link MonoCloudTokenError} - If the token is not active or claim validation fails.
   *
   * @throws {@link MonoCloudOPError} - When the introspection endpoint returns a standardized
   * OAuth 2.0 error response.
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   * @throws {@link MonoCloudValidationError} - When the access token is empty or the introspection
   * endpoint is not available in the issuer metadata or claims validation fails.
   *
   */
  async introspectAccessToken(
    accessToken: string,
    options?: IntrospectOptions
  ): Promise<AccessTokenClaims> {
    if (!this.clientId) {
      throw new MonoCloudValidationError(
        'The clientId option must be configured to introspect access tokens'
      );
    }

    if (typeof accessToken !== 'string' || accessToken.trim().length === 0) {
      throw new MonoCloudValidationError(
        'Access token must be a valid non-empty string'
      );
    }

    const metadata = await this.getMetadata();

    const introspectionEndpoint = this.resolveEndpoint(
      metadata,
      'introspection_endpoint'
    );

    const body = new URLSearchParams();
    body.set('token', accessToken);
    body.set('token_type_hint', 'access_token');

    const headers: Record<string, string> = {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    };

    await clientAuth(
      this.clientId,
      this.clientSecret,
      this.authMethod,
      this.tenantDomain,
      headers,
      body,
      JWT_ASSERTION_CLOCK_SKEW
    );

    const response = await innerFetch(
      introspectionEndpoint,
      {
        method: 'POST',
        body: body.toString(),
        headers,
      },
      this.fetcher
    );

    if (response.status === 400 || response.status === 401) {
      const standardBodyError = await deserializeJson(response);

      throw new MonoCloudOPError(
        standardBodyError.error ?? 'introspection_failed',
        standardBodyError.error_description ?? 'Token introspection failed'
      );
    }

    if (response.status !== 200) {
      throw new MonoCloudHttpError(
        `Error while performing token introspection. Unexpected status code: ${response.status}`,
        response.status,
        response.statusText
      );
    }

    const introspectionResponse = await deserializeJson<
      AccessTokenClaims & { active?: boolean }
    >(response);

    if (!introspectionResponse.active) {
      throw new MonoCloudTokenError('Token is not active');
    }

    const { active: _, ...claims } = introspectionResponse;

    this.validateAccessTokenClaims(claims, options?.scopes, options?.groups);

    if (options?.validateCertificateBinding) {
      await this.validateCertificateBinding(claims, options.clientCertificate);
    }

    return claims;
  }

  /**
   * Validates a JWT access token by verifying the signature and claims.
   *
   * @param accessToken - The access token JWT string to validate.
   * @param options - Validation options.
   *
   * @returns Validated access token claims.
   *
   * @throws {@link MonoCloudTokenError} - If JWT parsing, signature verification, or claim validation fails.
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   * @throws {@link MonoCloudValidationError} - When the access token is empty or claims validation fails.
   *
   */
  async validateJwtAccessToken(
    accessToken: string,
    options?: ValidateJwtAccessTokenOptions
  ): Promise<AccessTokenClaims> {
    if (typeof accessToken !== 'string' || accessToken.trim().length === 0) {
      throw new MonoCloudValidationError(
        'Access token must be a valid non-empty string'
      );
    }

    const {
      0: protectedHeader,
      1: payload,
      2: encodedSignature,
      length,
    } = accessToken.split('.');

    if (length !== 3) {
      throw new MonoCloudTokenError(
        'JWT access token must have a header, payload and signature'
      );
    }

    let header: JwsHeaderParameters;
    try {
      header = JSON.parse(decodeBase64Url(protectedHeader));
    } catch {
      throw new MonoCloudTokenError('Failed to parse JWT Header');
    }

    if (
      header === null ||
      typeof header !== 'object' ||
      Array.isArray(header)
    ) {
      throw new MonoCloudTokenError('JWT Header must be a top level object');
    }

    if (header.crit !== undefined) {
      throw new MonoCloudTokenError('Unexpected JWT "crit" header parameter');
    }

    const binary = decodeBase64Url(encodedSignature);

    const signature = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
      signature[i] = binary.charCodeAt(i);
    }

    const jwks = options?.jwks ?? (await this.getJwks());

    const key = await getPublicSigKeyFromIssuerJwks(jwks.keys, header);

    const input = `${protectedHeader}.${payload}`;

    const verified = await crypto.subtle.verify(
      keyToSubtle(key),
      key,
      signature,
      stringToArrayBuffer(input) as BufferSource
    );

    if (!verified) {
      throw new MonoCloudTokenError('JWT signature verification failed');
    }

    let claims: AccessTokenClaims;

    try {
      claims = JSON.parse(decodeBase64Url(payload));
    } catch {
      throw new MonoCloudTokenError('Failed to parse JWT Payload');
    }

    if (
      claims === null ||
      typeof claims !== 'object' ||
      Array.isArray(claims)
    ) {
      throw new MonoCloudTokenError('JWT Payload must be a top level object');
    }

    this.validateAccessTokenClaims(claims, options?.scopes, options?.groups);

    if (options?.validateCertificateBinding) {
      await this.validateCertificateBinding(claims, options.clientCertificate);
    }

    return claims;
  }

  /**
   * Sets clock skew used for access token time-based claim validation.
   *
   * @param clockSkew - Number of seconds to adjust the current time to account for clock differences.
   */
  public setClockSkew(clockSkew: number): void {
    this.clockSkew = clockSkew;
  }

  /**
   * Sets clock tolerance used for access token time-based claim validation.
   *
   * @param clockTolerance - Additional time tolerance in seconds for time-based claim validation.
   */
  public setClockTolerance(clockTolerance: number): void {
    this.clockTolerance = clockTolerance;
  }

  /**
   * Validates access token claims against the expected issuer, audience,
   * time-based claims, and any required scopes and groups.
   *
   * @param claims - The access token claims to validate.
   * @param scopes - Scopes the token must contain.
   * @param groups - Groups the token's subject must belong to.
   *
   * @throws {@link MonoCloudTokenError} - If any claim validation fails.
   */
  protected validateAccessTokenClaims(
    claims: AccessTokenClaims,
    scopes?: string[],
    groups?: string[]
  ): void {
    const current = now() + this.clockSkew;

    if (claims.iss !== this.tenantDomain) {
      throw new MonoCloudTokenError('Invalid Issuer');
    }

    if (claims.sub && typeof claims.sub !== 'string') {
      throw new MonoCloudTokenError('Invalid subject');
    }

    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];

    if (!audience.includes(this.audience)) {
      throw new MonoCloudTokenError('Invalid audience claim');
    }

    if (claims.exp !== undefined) {
      if (typeof claims.exp !== 'number') {
        throw new MonoCloudTokenError(
          'Unexpected "exp" (expiration time) claim type'
        );
      }

      if (claims.exp <= current - this.clockTolerance) {
        throw new MonoCloudTokenError(
          'Unexpected "exp" (expiration time) claim value, timestamp is <= now()'
        );
      }
    }

    if (claims.nbf !== undefined) {
      if (typeof claims.nbf !== 'number') {
        throw new MonoCloudTokenError(
          'Unexpected "nbf" (not before) claim type'
        );
      }

      if (claims.nbf > current + this.clockTolerance) {
        throw new MonoCloudTokenError(
          'Unexpected "nbf" (not before) claim value, timestamp is > now()'
        );
      }
    }

    if (scopes && scopes.length > 0) {
      const tokenScopes = new Set(parseSpaceSeparated(claims.scope));

      for (const requiredScope of scopes) {
        if (!tokenScopes.has(requiredScope)) {
          throw new MonoCloudTokenError(
            'Token is missing required scopes',
            'insufficient_scope'
          );
        }
      }
    }

    if (groups) {
      if (
        !isUserInGroup(
          claims,
          groups,
          this.groupOptions?.groupsClaim,
          this.groupOptions?.matchAll
        )
      ) {
        throw new MonoCloudTokenError(
          'Token is missing required groups',
          'insufficient_groups'
        );
      }
    }
  }

  /**
   * Validates that the access token is bound to the presented client
   * certificate by comparing the `cnf` claim's `x5t#S256` thumbprint against
   * the certificate's SHA-256 hash.
   *
   * @param accessTokenClaims - The access token claims containing the `cnf` claim.
   * @param certificate - The client certificate presented with the request.
   *
   * @throws {@link MonoCloudTokenError} - If the certificate is missing or malformed, the `cnf` claim is missing or invalid, or the hashes do not match.
   */
  protected async validateCertificateBinding(
    accessTokenClaims: AccessTokenClaims,
    certificate?: string
  ): Promise<void> {
    if (typeof certificate !== 'string' || certificate.trim().length === 0) {
      throw new MonoCloudTokenError('Client certificate is not present');
    }

    const pemMatch =
      /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(
        certificate
      );
    const encodedCertificate = (pemMatch?.[1] ?? certificate).replace(
      /\s+/g,
      ''
    );

    let certificateBinary: string;

    try {
      certificateBinary = atob(encodedCertificate);
    } catch {
      throw new MonoCloudTokenError('Client certificate is malformed');
    }

    const certificateBytes = new Uint8Array(certificateBinary.length);

    for (let i = 0; i < certificateBinary.length; i++) {
      certificateBytes[i] = certificateBinary.charCodeAt(i);
    }

    const certificateDigest = await crypto.subtle.digest(
      'SHA-256',
      certificateBytes
    );

    const clientCertHash = arrayBufferToBase64(
      new Uint8Array(certificateDigest)
    );

    let cnfClaimValue: unknown = accessTokenClaims.cnf;

    if (cnfClaimValue === undefined || cnfClaimValue === null) {
      throw new MonoCloudTokenError(
        "Access token does not contain a 'cnf' (confirmation) claim for certificate binding"
      );
    }

    if (typeof cnfClaimValue === 'string') {
      try {
        cnfClaimValue = JSON.parse(cnfClaimValue) as unknown;
      } catch {
        throw new MonoCloudTokenError(
          "Malformed 'cnf' claim for certificate binding"
        );
      }
    }

    if (
      cnfClaimValue === null ||
      typeof cnfClaimValue !== 'object' ||
      Array.isArray(cnfClaimValue)
    ) {
      throw new MonoCloudTokenError("The 'cnf' claim could not be parsed");
    }

    const certHash = (cnfClaimValue as Record<string, unknown>)['x5t#S256'];

    if (typeof certHash !== 'string' || certHash.length === 0) {
      throw new MonoCloudTokenError(
        "The 'cnf' claim does not contain an 'x5t#S256' member specifying the certificate hash for binding"
      );
    }

    if (!timingSafeEqual(certHash, clientCertHash)) {
      throw new MonoCloudTokenError(
        'The certificate hash in the access token does not match the presented client certificate (certificate binding validation failed)'
      );
    }
  }
}
