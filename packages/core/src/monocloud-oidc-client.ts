import {
  decodeBase64Url,
  findToken,
  getPublicSigKeyFromIssuerJwks,
  now,
  parseSpaceSeparated,
  stringToArrayBuffer,
} from './utils/internal';
import { clientAuth, keyToSubtle } from './client-auth';
import {
  AccessToken,
  AuthenticateOptions,
  AuthorizationParams,
  ClientAuthMethod,
  EndSessionParameters,
  IdTokenClaims,
  IssuerMetadata,
  Jwk,
  Jwks,
  JWSAlgorithm,
  JwsHeaderParameters,
  MonoCloudClientOptions,
  MonoCloudSession,
  MonoCloudUser,
  ParResponse,
  PushedAuthorizationParams,
  RefetchUserInfoOptions,
  RefreshGrantOptions,
  RefreshSessionOptions,
  Tokens,
  UserinfoResponse,
} from './types';
import { MonoCloudOPError } from './errors/monocloud-op-error';
import { MonoCloudHttpError } from './errors/monocloud-http-error';
import { MonoCloudValidationError } from './errors/monocloud-validation-error';
import { MonoCloudTokenError } from './errors/monocloud-token-error';
import { MonoCloudAuthBaseError } from './errors/monocloud-auth-base-error';

const JWT_ASSERTION_CLOCK_SKEW = 5;

const FILTER_ID_TOKEN_CLAIMS = [
  'iss',
  'exp',
  'nbf',
  'aud',
  'nonce',
  'iat',
  'auth_time',
  'c_hash',
  'at_hash',
  's_hash',
];

function assertMetadataProperty<K extends keyof IssuerMetadata>(
  metadata: IssuerMetadata,
  property: K
): asserts metadata is IssuerMetadata & Required<Pick<IssuerMetadata, K>> {
  if (metadata[property] === undefined || metadata[property] === null) {
    throw new MonoCloudValidationError(
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
    throw new MonoCloudHttpError(
      (e as any).message ?? 'Unexpected Network Error'
    );
  }
};

const deserializeJson = async <T = any>(res: Response): Promise<T> => {
  try {
    return await res.json();
  } catch (e) {
    throw new MonoCloudHttpError(
      /* v8 ignore next -- @preserve */
      `Failed to parse response body as JSON ${(e as any).message ? `: ${(e as any).message}` : ''}`
    );
  }
};

export class MonoCloudOidcClient {
  private readonly tenantDomain: string;

  private readonly clientId: string;

  private readonly clientSecret?: string | Jwk;

  private readonly authMethod: ClientAuthMethod;

  private readonly idTokenSigningAlgorithm: JWSAlgorithm;

  private jwks?: Jwks;

  private jwksCacheExpiry = 0;

  private jwksCacheDuration = 60;

  private metadata?: IssuerMetadata;

  private metadataCacheExpiry = 0;

  private metadataCacheDuration = 60;

  constructor(
    tenantDomain: string,
    clientId: string,
    options?: MonoCloudClientOptions
  ) {
    // eslint-disable-next-line no-param-reassign
    tenantDomain ??= '';
    /* v8 ignore next -- @preserve */
    this.tenantDomain = `${!tenantDomain.startsWith('https://') ? 'https://' : ''}${tenantDomain.endsWith('/') ? tenantDomain.slice(0, -1) : tenantDomain}`;
    this.clientId = clientId;
    this.clientSecret = options?.clientSecret;
    this.authMethod = options?.clientAuthMethod ?? 'client_secret_basic';
    this.idTokenSigningAlgorithm = options?.idTokenSigningAlgorithm ?? 'RS256';

    if (options?.jwksCacheDuration) {
      this.jwksCacheDuration = options.jwksCacheDuration;
    }

    if (options?.metadataCacheDuration) {
      this.metadataCacheDuration = options.metadataCacheDuration;
    }
  }

  /**
   * Generates an authorization URL with specified parameters.
   *
   * If no values are provided for `responseType`, or `codeChallengeMethod`, they default to `code`, and `S256`, respectively.
   *
   * @param params Authorization URL parameters
   *
   * @returns Tenant's authorization url.
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async authorizationUrl(params: AuthorizationParams): Promise<string> {
    const queryParams = new URLSearchParams();

    queryParams.set('client_id', this.clientId);

    if (params.redirectUri) {
      queryParams.set('redirect_uri', params.redirectUri);
    }

    if (params.requestUri) {
      queryParams.set('request_uri', params.requestUri);
    }

    const scopes = parseSpaceSeparated(params.scopes) ?? [];

    if (scopes.length > 0) {
      queryParams.set('scope', scopes.join(' '));
    }

    if (params.responseType && params.responseType.length > 0) {
      queryParams.set('response_type', params.responseType);
    }

    if (
      (!params.responseType || params.responseType.length === 0) &&
      !params.requestUri
    ) {
      queryParams.set('response_type', 'code');
    }

    if (params.authenticatorHint) {
      queryParams.set('authenticator_hint', params.authenticatorHint);
    }

    if (params.loginHint) {
      queryParams.set('login_hint', params.loginHint);
    }

    if (params.request) {
      queryParams.set('request', params.request);
    }

    if (params.responseMode) {
      queryParams.set('response_mode', params.responseMode);
    }

    if (params.acrValues && params.acrValues.length > 0) {
      queryParams.set('acr_values', params.acrValues.join(' '));
    }

    if (params.nonce) {
      queryParams.set('nonce', params.nonce);
    }

    if (params.uiLocales) {
      queryParams.set('ui_locales', params.uiLocales);
    }

    if (params.display) {
      queryParams.set('display', params.display);
    }

    if (typeof params.maxAge === 'number') {
      queryParams.set('max_age', params.maxAge.toString());
    }

    if (params.prompt) {
      queryParams.set('prompt', params.prompt);
    }

    const resource = parseSpaceSeparated(params.resource) ?? [];

    if (resource.length > 0) {
      for (const r of resource) {
        queryParams.append('resource', r);
      }
    }

    if (params.codeChallenge) {
      queryParams.set('code_challenge', params.codeChallenge);
      queryParams.set(
        'code_challenge_method',
        params.codeChallengeMethod ?? 'S256'
      );
    }

    if (params.state) {
      queryParams.set('state', params.state);
    }

    const metadata = await this.getMetadata();

    assertMetadataProperty(metadata, 'authorization_endpoint');

    return `${metadata.authorization_endpoint}?${queryParams.toString()}`;
  }

  /**
   * Fetches the authorization server metadata from the .well-known endpoint.
   * The metadata is cached for 1 minute.
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
      `${this.tenantDomain}/.well-known/openid-configuration`
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
   * Fetches the JSON Web Keys used to sign the id token.
   * The JWKS is cached for 1 minute.
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

    const response = await innerFetch(metadata.jwks_uri);

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
   * Performs a pushed authorization request.
   *
   * @param params - Authorization Parameters
   *
   * @returns Response from Pushed Authorization Request (PAR) endpoint
   *
   * @throws {@link MonoCloudOPError} - When the request is invalid.
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async pushedAuthorizationRequest(
    params: PushedAuthorizationParams
  ): Promise<ParResponse> {
    const body = new URLSearchParams();

    body.set('client_id', this.clientId);

    if (params.redirectUri) {
      body.set('redirect_uri', params.redirectUri);
    }

    const scopes = parseSpaceSeparated(params.scopes) ?? [];

    if (scopes.length > 0) {
      body.set('scope', scopes.join(' '));
    }

    if (params.responseType && params.responseType.length > 0) {
      body.set('response_type', params.responseType);
    } else {
      body.set('response_type', 'code');
    }

    if (params.authenticatorHint) {
      body.set('authenticator_hint', params.authenticatorHint);
    }

    if (params.loginHint) {
      body.set('login_hint', params.loginHint);
    }

    if (params.request) {
      body.set('request', params.request);
    }

    if (params.responseMode) {
      body.set('response_mode', params.responseMode);
    }

    if (params.acrValues && params.acrValues.length > 0) {
      body.set('acr_values', params.acrValues.join(' '));
    }

    if (params.nonce) {
      body.set('nonce', params.nonce);
    }

    if (params.uiLocales) {
      body.set('ui_locales', params.uiLocales);
    }

    if (params.display) {
      body.set('display', params.display);
    }

    if (typeof params.maxAge === 'number') {
      body.set('max_age', params.maxAge.toString());
    }

    if (params.prompt) {
      body.set('prompt', params.prompt);
    }

    const resource = parseSpaceSeparated(params.resource) ?? [];

    if (resource.length > 0) {
      for (const r of resource) {
        body.append('resource', r);
      }
    }

    if (params.codeChallenge) {
      body.set('code_challenge', params.codeChallenge);
      body.set('code_challenge_method', params.codeChallengeMethod ?? 'S256');
    }

    if (params.state) {
      body.set('state', params.state);
    }

    const headers = {
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

    const metadata = await this.getMetadata();

    assertMetadataProperty(metadata, 'pushed_authorization_request_endpoint');

    const response = await innerFetch(
      metadata.pushed_authorization_request_endpoint,
      {
        body: body.toString(),
        method: 'POST',
        headers,
      }
    );

    if (response.status === 400) {
      const standardBodyError = await deserializeJson(response);

      throw new MonoCloudOPError(
        standardBodyError.error ?? 'par_request_failed',
        standardBodyError.error_description ??
          'Pushed Authorization Request Failed'
      );
    }

    if (response.status !== 201) {
      throw new MonoCloudHttpError(
        `Error while performing pushed authorization request. Unexpected status code: ${response.status}`
      );
    }

    return await deserializeJson<ParResponse>(response);
  }

  /**
   * Fetches userinfo associated with the provided access token.
   *
   * @param accessToken - A valid access token used to retrieve userinfo.
   *
   * @returns The authenticated user's claims.
   *
   * @throws {@link MonoCloudOPError} - When the OpenID Provider returns a standardized
   * OAuth 2.0 error (e.g., 'invalid_token') in the 'WWW-Authenticate' header
   * following a 401 Unauthorized response.
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   * @throws {@link MonoCloudValidationError} - When the access token is invalid.
   *
   */
  async userinfo(accessToken: string): Promise<UserinfoResponse> {
    if (!accessToken.trim().length) {
      throw new MonoCloudValidationError(
        'Access token is required for fetching userinfo'
      );
    }

    const metadata = await this.getMetadata();

    assertMetadataProperty(metadata, 'userinfo_endpoint');

    const response = await innerFetch(metadata.userinfo_endpoint, {
      method: 'GET',
      headers: {
        authorization: `Bearer ${accessToken}`,
      },
    });

    if (response.status === 401) {
      const authenticateError = response.headers.get('WWW-Authenticate');

      if (authenticateError) {
        const errorMatch = /error="([^"]+)"/.exec(authenticateError);
        const error = errorMatch ? errorMatch[1] : 'userinfo_failed';

        const errorDescMatch = /error_description="([^"]+)"/.exec(
          authenticateError
        );

        const errorDescription = errorDescMatch
          ? errorDescMatch[1]
          : 'Userinfo authentication error';

        throw new MonoCloudOPError(error, errorDescription);
      }
    }

    if (response.status !== 200) {
      throw new MonoCloudHttpError(
        `Error while fetching userinfo. Unexpected status code: ${response.status}`
      );
    }

    return await deserializeJson<UserinfoResponse>(response);
  }

  /**
   * Generates OpenID end session url for signing out.
   *
   * Note - The `state` is added only when `postLogoutRedirectUri` is present.
   *
   * @param params - Parameters to build end session url
   *
   * @returns Tenant's end session url
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async endSessionUrl(params: EndSessionParameters): Promise<string> {
    const queryParams = new URLSearchParams();

    queryParams.set('client_id', this.clientId);

    if (params.idToken) {
      queryParams.set('id_token_hint', params.idToken);
    }

    if (params.postLogoutRedirectUri) {
      queryParams.set('post_logout_redirect_uri', params.postLogoutRedirectUri);

      if (params.state) {
        queryParams.set('state', params.state);
      }
    }

    const metadata = await this.getMetadata();

    assertMetadataProperty(metadata, 'end_session_endpoint');

    return `${metadata.end_session_endpoint}?${queryParams.toString()}`;
  }

  /**
   * Exchanges an authorization code for tokens.
   *
   * @param code - The authorization code received from the authorization server.
   * @param redirectUri - The redirect URI used in the initial authorization request.
   * @param codeVerifier - Code verifier for PKCE.
   * @param resource - Space-separated list of resources the access token should be scoped to
   *
   * @returns Tokens obtained by exchanging an authorization code at the token endpoint.
   *
   * @throws {@link MonoCloudOPError} - When the OpenID Provider returns a standardized
   * OAuth 2.0 error response.
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async exchangeAuthorizationCode(
    code: string,
    redirectUri: string,
    codeVerifier?: string,
    resource?: string
  ): Promise<Tokens> {
    const body = new URLSearchParams();

    body.set('grant_type', 'authorization_code');
    body.set('code', code);
    body.set('redirect_uri', redirectUri);

    if (codeVerifier) {
      body.set('code_verifier', codeVerifier);
    }

    const resources = parseSpaceSeparated(resource) ?? [];

    if (resources.length > 0) {
      for (const r of resources) {
        body.append('resource', r);
      }
    }

    const headers = {
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

    const metadata = await this.getMetadata();

    assertMetadataProperty(metadata, 'token_endpoint');

    const response = await innerFetch(metadata.token_endpoint, {
      method: 'POST',
      body: body.toString(),
      headers,
    });

    if (response.status === 400) {
      const standardBodyError = await deserializeJson(response);

      throw new MonoCloudOPError(
        standardBodyError.error ?? 'code_grant_failed',
        standardBodyError.error_description ?? 'Authorization code grant failed'
      );
    }

    if (response.status !== 200) {
      throw new MonoCloudHttpError(
        `Error while performing token grant. Unexpected status code: ${response.status}`
      );
    }

    return await deserializeJson<Tokens>(response);
  }

  /**
   * Exchanges a refresh token for new tokens.
   *
   * @param refreshToken - The refresh token used to request new tokens.
   * @param options - Refresh grant options.
   *
   * @returns Tokens obtained by exchanging a refresh token at the token endpoint.
   *
   * @throws {@link MonoCloudOPError} - When the OpenID Provider returns a standardized
   * OAuth 2.0 error response.
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async refreshGrant(
    refreshToken: string,
    options?: RefreshGrantOptions
  ): Promise<Tokens> {
    const body = new URLSearchParams();

    body.set('grant_type', 'refresh_token');
    body.set('refresh_token', refreshToken);

    const scopes = parseSpaceSeparated(options?.scopes) ?? [];

    if (scopes.length > 0) {
      body.set('scope', scopes.join(' '));
    }

    const resource = parseSpaceSeparated(options?.resource) ?? [];

    if (resource.length > 0) {
      for (const r of resource) {
        body.append('resource', r);
      }
    }

    const headers = {
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

    const metadata = await this.getMetadata();

    assertMetadataProperty(metadata, 'token_endpoint');

    const response = await innerFetch(metadata.token_endpoint, {
      method: 'POST',
      body: body.toString(),
      headers,
    });

    if (response.status === 400) {
      const standardBodyError = await deserializeJson(response);

      throw new MonoCloudOPError(
        standardBodyError.error ?? 'refresh_grant_failed',
        standardBodyError.error_description ?? 'Refresh token grant failed'
      );
    }

    if (response.status !== 200) {
      throw new MonoCloudHttpError(
        `Error while performing refresh token grant. Unexpected status code: ${response.status}`
      );
    }

    return await deserializeJson<Tokens>(response);
  }

  /**
   * Generates a session with user and tokens by exchanging authorization code from callback params.
   *
   * @param code - The authorization code received from the callback
   * @param redirectUri - The redirect URI that was used in the authorization request
   * @param requestedScopes - A space-separated list of scopes originally requested via the `/authorize` endpoint.
   * This is stored in the session to ensure the correct access token can be identified and refreshed during `refreshSession()`.
   * @param resource - A space-separated list of resource indicators originally requested via the `/authorize` endpoint.
   * Used alongside scopes to uniquely identify and refresh the specific access token associated with these resources.
   * @param options - Options for authenticating a user with authorization code
   *
   * @returns The user's session containing authentication tokens and user information.
   *
   * @throws {@link MonoCloudValidationError} - When the token scope does not contain the openid scope,
   * or if 'expires_in' or 'scope' is missing from the token response.
   *
   * @throws {@link MonoCloudOPError} - When the OpenID Provider returns a standardized
   * OAuth 2.0 error response.
   *
   * @throws {@link MonoCloudTokenError} - If ID Token validation fails
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async authenticate(
    code: string,
    redirectUri: string,
    requestedScopes: string,
    resource?: string,
    options?: AuthenticateOptions
  ): Promise<MonoCloudSession> {
    const tokens = await this.exchangeAuthorizationCode(
      code,
      redirectUri,
      options?.codeVerifier,
      resource
    );

    const accessTokenExpiration =
      typeof tokens.expires_in === 'number'
        ? now() + tokens.expires_in
        : undefined;

    if (!accessTokenExpiration) {
      throw new MonoCloudValidationError("Missing required 'expires_in' field");
    }

    if (!tokens.scope) {
      throw new MonoCloudValidationError("Missing or invalid 'scope' field");
    }

    let userinfo: MonoCloudUser | undefined;

    if (options?.fetchUserInfo && tokens.scope?.includes('openid')) {
      userinfo = await this.userinfo(tokens.access_token);
    }

    let idTokenClaims: Partial<IdTokenClaims> = {};

    if (tokens.id_token) {
      if (options?.validateIdToken ?? true) {
        const jwks = options?.jwks ?? (await this.getJwks());

        idTokenClaims = await this.validateIdToken(
          tokens.id_token,
          jwks.keys,
          options?.idTokenClockSkew ?? 0,
          options?.idTokenClockTolerance ?? 0,
          options?.idTokenMaxAge,
          options?.idTokenNonce
        );
      } else {
        idTokenClaims = MonoCloudOidcClient.decodeJwt(tokens.id_token);
      }
    }

    (options?.filteredIdTokenClaims ?? FILTER_ID_TOKEN_CLAIMS).forEach(x => {
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete idTokenClaims[x];
    });

    const session: MonoCloudSession = {
      user: {
        ...idTokenClaims,
        ...(userinfo ?? {}),
      } as MonoCloudUser,
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token,
      authorizedScopes: requestedScopes,
      accessTokens: [
        {
          scopes: tokens.scope,
          accessToken: tokens.access_token,
          accessTokenExpiration,
          resource,
          requestedScopes,
        },
      ],
    };

    await options?.onSessionCreating?.(session, idTokenClaims, userinfo);

    return session;
  }

  /**
   * Refetches user information for an existing session using the userinfo endpoint.
   * Updates the session's user object with the latest user information while preserving existing properties.
   *
   * @param accessToken - Access token used to fetch the userinfo
   * @param session - The current MonoCloudSession
   * @param options - Userinfo refetch options
   *
   * @returns Updated session with the latest userinfo
   *
   * @throws {@link MonoCloudValidationError} - When the token scope does not contain openid scope
   *
   * @throws {@link MonoCloudOPError} - When the OpenID Provider returns a standardized
   * OAuth 2.0 error response.
   *
   * @throws {@link MonoCloudTokenError} - If ID Token validation fails
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async refetchUserInfo(
    accessToken: AccessToken,
    session: MonoCloudSession,
    options?: RefetchUserInfoOptions
  ): Promise<MonoCloudSession> {
    if (!accessToken.scopes?.includes('openid')) {
      throw new MonoCloudValidationError(
        'Fetching userinfo requires the openid scope'
      );
    }

    const userinfo = await this.userinfo(accessToken.accessToken);

    // eslint-disable-next-line no-param-reassign
    session.user = { ...session.user, ...userinfo };

    await options?.onSessionCreating?.(session, undefined, userinfo);

    return session;
  }

  /**
   * Refreshes an existing session using the refresh token.
   * This function requests new tokens using the refresh token and optionally updates user information.
   *
   * @param session - The current MonoCloudSession containing the refresh token
   * @param options - Session refresh options
   *
   * @returns User's session containing refreshed authentication tokens and user information.
   *
   * @throws {@link MonoCloudValidationError} - If the refresh token is not present in the session,
   * or if 'expires_in' or 'scope' (including the openid scope) is missing from the token response.
   *
   * @throws {@link MonoCloudOPError} - When the OpenID Provider returns a standardized
   * OAuth 2.0 error response.
   *
   * @throws {@link MonoCloudTokenError} - If ID Token validation fails
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async refreshSession(
    session: MonoCloudSession,
    options?: RefreshSessionOptions
  ): Promise<MonoCloudSession> {
    if (!session.refreshToken) {
      throw new MonoCloudValidationError(
        'Session does not contain refresh token'
      );
    }

    const tokens = await this.refreshGrant(
      session.refreshToken,
      options?.refreshGrantOptions
    );

    const accessTokenExpiration =
      typeof tokens.expires_in === 'number'
        ? now() + tokens.expires_in
        : undefined;

    if (!accessTokenExpiration) {
      throw new MonoCloudValidationError("Missing required 'expires_in' field");
    }

    if (!tokens.scope) {
      throw new MonoCloudValidationError("Missing or invalid 'scope' field");
    }

    let userinfo: MonoCloudUser | undefined;

    if (options?.fetchUserInfo && tokens.scope?.includes('openid')) {
      userinfo = await this.userinfo(tokens.access_token);
    }

    let idTokenClaims: Partial<IdTokenClaims> = {};

    if (tokens.id_token) {
      if (options?.validateIdToken ?? true) {
        const jwks = options?.jwks ?? (await this.getJwks());

        idTokenClaims = await this.validateIdToken(
          tokens.id_token,
          jwks.keys,
          options?.idTokenClockSkew ?? 0,
          options?.idTokenClockTolerance ?? 0
        );
      } else {
        idTokenClaims = MonoCloudOidcClient.decodeJwt(tokens.id_token);
      }
    }

    (options?.filteredIdTokenClaims ?? FILTER_ID_TOKEN_CLAIMS).forEach(x => {
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete idTokenClaims[x];
    });

    const resource = options?.refreshGrantOptions?.resource;
    let scopes = options?.refreshGrantOptions?.scopes;

    if (!resource && !scopes) {
      scopes = session.authorizedScopes;
    }

    const accessToken = findToken(session.accessTokens, resource, scopes);

    const user =
      Object.keys(idTokenClaims).length === 0 && !userinfo
        ? session.user
        : ({
            ...session.user,
            ...idTokenClaims,
            ...(userinfo ?? {}),
          } as MonoCloudUser);

    const newTokens =
      session.accessTokens?.filter(t => t !== accessToken) ?? [];

    newTokens.push({
      scopes: tokens.scope,
      accessToken: tokens.access_token,
      accessTokenExpiration,
      resource,
      requestedScopes: scopes,
    });

    const updatedSession: MonoCloudSession = {
      ...session,
      user,
      idToken: tokens.id_token ?? session.idToken,
      refreshToken: tokens.refresh_token ?? session.refreshToken,
      accessTokens: newTokens,
    };

    await options?.onSessionCreating?.(updatedSession, idTokenClaims, userinfo);

    return updatedSession;
  }

  /**
   * Revokes an access token or refresh token, rendering it invalid for future use.
   *
   * @param token - The token string to be revoked
   * @param tokenType - Hint about the token type ('access_token' or 'refresh_token')
   *
   * @returns If token revocation succeeded
   *
   * @throws {@link MonoCloudValidationError} - If token is invalid or unsupported token type
   *
   * @throws {@link MonoCloudOPError} - When the OpenID Provider returns a standardized
   * OAuth 2.0 error response.
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   */
  async revokeToken(token: string, tokenType?: string): Promise<void> {
    if (!token.trim().length) {
      throw new MonoCloudValidationError('Invalid token');
    }

    if (
      tokenType &&
      tokenType !== 'access_token' &&
      tokenType !== 'refresh_token'
    ) {
      throw new MonoCloudValidationError(
        'Only access_token and refresh_token types are supported.'
      );
    }

    const body = new URLSearchParams();
    body.set('token', token);
    if (tokenType) {
      body.set('token_type_hint', tokenType);
    }

    const headers = {
      'content-type': 'application/x-www-form-urlencoded',
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

    const metadata = await this.getMetadata();

    assertMetadataProperty(metadata, 'revocation_endpoint');

    const response = await innerFetch(metadata.revocation_endpoint, {
      method: 'POST',
      body: body.toString(),
      headers,
    });

    if (response.status === 400) {
      const standardBodyError = await deserializeJson(response);

      throw new MonoCloudOPError(
        standardBodyError.error ?? 'revocation_failed',
        standardBodyError.error_description ?? 'Token revocation failed'
      );
    }

    if (response.status !== 200) {
      throw new MonoCloudHttpError(
        `Error while performing revocation request. Unexpected status code: ${response.status}`
      );
    }
  }

  /**
   * Validates an ID Token.
   *
   * @param idToken - The ID Token JWT string to validate
   * @param jwks - Array of JSON Web Keys (JWK) used to verify the token's signature
   * @param clockSkew - Number of seconds to adjust the current time to account for clock differences
   * @param clockTolerance - Additional time tolerance in seconds for time-based claim validation
   * @param maxAge - maximum authentication age in seconds
   * @param nonce - nonce value to validate against the token's nonce claim
   *
   * @returns Validated ID Token claims
   *
   * @throws {@link MonoCloudTokenError} - If ID Token validation fails
   *
   */
  async validateIdToken(
    idToken: string,
    jwks: Jwk[],
    clockSkew: number,
    clockTolerance: number,
    maxAge?: number,
    nonce?: string
  ): Promise<IdTokenClaims> {
    if (typeof idToken !== 'string' || idToken.trim().length === 0) {
      throw new MonoCloudTokenError(
        'ID Token must be a valid non-empty string'
      );
    }

    const {
      0: protectedHeader,
      1: payload,
      2: encodedSignature,
      length,
    } = idToken.split('.');

    if (length !== 3) {
      throw new MonoCloudTokenError(
        'ID Token must have a header, payload and signature'
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

    if (this.idTokenSigningAlgorithm !== header.alg) {
      throw new MonoCloudTokenError('Invalid signing alg');
    }

    if (header.crit !== undefined) {
      throw new MonoCloudTokenError('Unexpected JWT "crit" header parameter');
    }

    const binary = decodeBase64Url(encodedSignature);

    const signature = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
      signature[i] = binary.charCodeAt(i);
    }

    const key = await getPublicSigKeyFromIssuerJwks(jwks, header);

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

    let claims: IdTokenClaims;

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

    if ((claims.nonce || nonce) && claims.nonce !== nonce) {
      throw new MonoCloudTokenError('Nonce mismatch');
    }

    const current = now() + clockSkew;

    /* v8 ignore else -- @preserve */
    if (claims.exp !== undefined) {
      if (typeof claims.exp !== 'number') {
        throw new MonoCloudTokenError(
          'Unexpected JWT "exp" (expiration time) claim type'
        );
      }

      if (claims.exp <= current - clockTolerance) {
        throw new MonoCloudTokenError(
          'Unexpected JWT "exp" (expiration time) claim value, timestamp is <= now()'
        );
      }
    }

    /* v8 ignore else -- @preserve */
    if (claims.iat !== undefined) {
      if (typeof claims.iat !== 'number') {
        throw new MonoCloudTokenError(
          'Unexpected JWT "iat" (issued at) claim type'
        );
      }
    }

    if (
      typeof claims.auth_time === 'number' &&
      typeof maxAge === 'number' &&
      claims.auth_time + maxAge < current
    ) {
      throw new MonoCloudTokenError(
        'Too much time has elapsed since the last End-User authentication'
      );
    }

    if (claims.iss !== this.tenantDomain) {
      throw new MonoCloudTokenError('Invalid Issuer');
    }

    if (claims.nbf !== undefined) {
      if (typeof claims.nbf !== 'number') {
        throw new MonoCloudTokenError(
          'Unexpected JWT "nbf" (not before) claim type'
        );
      }

      if (claims.nbf > current + clockTolerance) {
        throw new MonoCloudTokenError(
          'Unexpected JWT "nbf" (not before) claim value, timestamp is > now()'
        );
      }
    }

    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];

    if (!audience.includes(this.clientId)) {
      throw new MonoCloudTokenError('Invalid audience claim');
    }

    return claims;
  }

  /**
   * Decodes the payload of a JSON Web Token (JWT) and returns it as an object.
   * **THIS METHOD DOES NOT VERIFY JWT TOKENS**.
   *
   * @param jwt - JWT to decode
   *
   * @returns Decoded payload
   *
   * @throws {@link MonoCloudTokenError} - If decoding fails
   *
   */
  static decodeJwt(jwt: string): IdTokenClaims {
    try {
      const [, payload] = jwt.split('.');

      if (!payload?.trim()) {
        throw new MonoCloudTokenError('JWT does not contain payload');
      }

      const decoded = decodeBase64Url(payload);

      if (!decoded.startsWith('{')) {
        throw new MonoCloudTokenError('Payload is not an object');
      }

      return JSON.parse(decoded) as IdTokenClaims;
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
