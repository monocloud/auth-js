import {
  decodeBase64Url,
  findToken,
  profileSync,
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
  Jwk,
  SecurityAlgorithms,
  JwsHeaderParameters,
  MonoCloudOidcClientOptions,
  MonoCloudSession,
  MonoCloudUser,
  ParResponse,
  PushedAuthorizationParams,
  RefetchUserInfoOptions,
  RefreshGrantOptions,
  RefreshSessionOptions,
  Tokens,
  UserinfoResponse,
  DeviceAuthorizationParams,
  DeviceAuthorizationResponse,
} from './types';
import { MonoCloudOPError } from './errors/monocloud-op-error';
import { MonoCloudHttpError } from './errors/monocloud-http-error';
import { MonoCloudValidationError } from './errors/monocloud-validation-error';
import { MonoCloudTokenError } from './errors/monocloud-token-error';
import { MonoCloudOidcClientBase } from './monocloud-oidc-client-base';
import {
  assertMetadataProperty,
  deserializeJson,
  innerFetch,
  JWT_ASSERTION_CLOCK_SKEW,
} from './helper';

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

/**
 * @category Classes
 */
export class MonoCloudOidcClient extends MonoCloudOidcClientBase {
  private readonly clientId: string;

  private readonly clientSecret?: string | Jwk;

  private readonly authMethod: ClientAuthMethod;

  private readonly idTokenSigningAlgorithm: SecurityAlgorithms;

  /**
   * Creates a new instance of MonoCloudOidcClient.
   *
   * @param tenantDomain - The tenant domain URL.
   * @param clientId - Client id of the application registered in MonoCloud.
   * @param options - Additional client configuration options.
   */
  constructor(
    tenantDomain: string,
    clientId: string,
    options?: MonoCloudOidcClientOptions
  ) {
    super(
      tenantDomain,
      options?.metadataCacheDuration,
      options?.jwksCacheDuration,
      options?.fetcher
    );
    this.clientId = clientId;
    this.clientSecret = options?.clientSecret;
    this.authMethod = options?.clientAuthMethod ?? 'client_secret_basic';
    this.idTokenSigningAlgorithm = options?.idTokenSigningAlgorithm ?? 'RS256';
  }

  /**
   * Generates an authorization URL with specified parameters.
   *
   * If no values are provided for `responseType`, or `codeChallengeMethod`, they default to `code`, and `S256`, respectively.
   *
   * @param params - Authorization URL parameters.
   *
   * @returns Tenant's authorization URL.
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
   * Performs a pushed authorization request.
   *
   * @param params - Authorization Parameters.
   *
   * @returns Response from Pushed Authorization Request (PAR) endpoint.
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
      },
      this.fetcher
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

    const response = await innerFetch(
      metadata.userinfo_endpoint,
      {
        method: 'GET',
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
      },
      this.fetcher
    );

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
   * Generates OpenID end session URL for signing out.
   *
   * Note - The `state` is added only when `postLogoutRedirectUri` is present.
   *
   * @param params - Parameters to build end session URL.
   *
   * @returns Tenant's end session URL.
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
   * @param resource - Space-separated list of resources the access token should be scoped to.
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

    const response = await innerFetch(
      metadata.token_endpoint,
      {
        method: 'POST',
        body: body.toString(),
        headers,
      },
      this.fetcher
    );

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

    const response = await innerFetch(
      metadata.token_endpoint,
      {
        method: 'POST',
        body: body.toString(),
        headers,
      },
      this.fetcher
    );

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
   * @param code - The authorization code received from the callback.
   * @param redirectUri - The redirect URI that was used in the authorization request.
   * @param requestedScopes - A space-separated list of scopes originally requested via the `/authorize` endpoint.
   * This is stored in the session to ensure the correct access token can be identified and refreshed during `refreshSession()`.
   * @param resource - A space-separated list of resource indicators originally requested via the `/authorize` endpoint.
   * Used alongside scopes to uniquely identify and refresh the specific access token associated with these resources.
   * @param options - Options for authenticating a user with authorization code.
   *
   * @returns The user's session containing authentication tokens and user information.
   *
   * @throws {@link MonoCloudValidationError} - When the token scope does not contain the openid scope,
   * or if 'expires_in' or 'scope' is missing from the token response.
   *
   * @throws {@link MonoCloudOPError} - When the OpenID Provider returns a standardized.
   * OAuth 2.0 error response.
   *
   * @throws {@link MonoCloudTokenError} - If ID Token validation fails.
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
          options?.idTokenClockTolerance ?? 60,
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
      user: profileSync(undefined, idTokenClaims, userinfo, true),
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
   * Updates the session's user object with the latest user information.
   *
   * @param accessToken - Access token used to fetch the userinfo.
   * @param session - The current MonoCloudSession.
   * @param options - Userinfo refetch options.
   *
   * @returns Updated session with the latest userinfo.
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

    const idTokenClaims =
      session.idToken && options?.strictProfileSync
        ? MonoCloudOidcClient.decodeJwt(session.idToken)
        : undefined;

    // eslint-disable-next-line no-param-reassign
    session.user = profileSync(
      session.user,
      idTokenClaims,
      userinfo,
      options?.strictProfileSync
    );

    await options?.onSessionCreating?.(session, undefined, userinfo);

    return session;
  }

  /**
   * Refreshes an existing session using the refresh token.
   * This function requests new tokens using the refresh token and optionally updates user information.
   *
   * @param session - The current MonoCloudSession containing the refresh token.
   * @param options - Session refresh options.
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
          options?.idTokenClockTolerance ?? 60
        );
      } else {
        idTokenClaims = MonoCloudOidcClient.decodeJwt(tokens.id_token);
      }
    } else if (session.idToken) {
      idTokenClaims = MonoCloudOidcClient.decodeJwt(session.idToken);
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

    const user = profileSync(
      session.user,
      idTokenClaims,
      userinfo,
      options?.strictProfileSync
    );

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
   * @param token - The token string to be revoked.
   * @param tokenType - Hint about the token type ('access_token' or 'refresh_token').
   *
   * @returns If token revocation succeeded.
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

    const response = await innerFetch(
      metadata.revocation_endpoint,
      {
        method: 'POST',
        body: body.toString(),
        headers,
      },
      this.fetcher
    );

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
   * @param idToken - The ID Token JWT string to validate.
   * @param jwks - Array of JSON Web Keys (JWK) used to verify the token's signature.
   * @param clockSkew - Number of seconds to adjust the current time to account for clock differences.
   * @param clockTolerance - Additional time tolerance in seconds for time-based claim validation.
   * @param maxAge - Maximum authentication age in seconds.
   * @param nonce - Nonce value to validate against the token's nonce claim.
   *
   * @returns Validated ID Token claims.
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
      claims.auth_time + maxAge < current - clockTolerance
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
   * Performs a device authorization request.
   *
   * @param params - Device Authorization Parameters.
   *
   * @returns Response from Device Authorization endpoint.
   *
   * @throws {@link MonoCloudOPError} - When the request is invalid.
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async deviceAuthorizationRequest(
    params: DeviceAuthorizationParams
  ): Promise<DeviceAuthorizationResponse> {
    const body = new URLSearchParams();

    body.set('client_id', this.clientId);

    const scopes = parseSpaceSeparated(params.scopes) ?? [];

    if (scopes.length > 0) {
      body.set('scope', scopes.join(' '));
    }

    const resource = parseSpaceSeparated(params?.resource) ?? [];

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

    assertMetadataProperty(metadata, 'device_authorization_endpoint');

    const response = await innerFetch(
      metadata.device_authorization_endpoint,
      {
        body: body.toString(),
        method: 'POST',
        headers,
      },
      this.fetcher
    );

    if (response.status === 400) {
      const standardBodyError = await deserializeJson(response);

      throw new MonoCloudOPError(
        standardBodyError.error ?? 'device_authorization_failed',
        standardBodyError.error_description ??
          'Device Authorization Request Failed'
      );
    }

    if (response.status !== 200) {
      throw new MonoCloudHttpError(
        `Error while performing device authorization request. Unexpected status code: ${response.status}`
      );
    }

    return await deserializeJson<DeviceAuthorizationResponse>(response);
  }

  /**
   * Exchanges a device code for tokens.
   *
   * @param deviceCode - The device code received from the device authorization server.
   *
   * @returns Tokens obtained by exchanging a device code at the token endpoint.
   *
   * @throws {@link MonoCloudOPError} - When the authorization server returns a standardized
   * OAuth 2.0 error response.
   *
   * @throws {@link MonoCloudHttpError} - Thrown if there is a network error during the request or
   * unexpected status code during the request or a serialization error while processing the response.
   *
   */
  async deviceAuthorizationGrant(deviceCode: string): Promise<Tokens> {
    const body = new URLSearchParams();

    body.set('grant_type', 'urn:ietf:params:oauth:grant-type:device_code');
    body.set('device_code', deviceCode);

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

    const response = await innerFetch(
      metadata.token_endpoint,
      {
        method: 'POST',
        body: body.toString(),
        headers,
      },
      this.fetcher
    );

    if (response.status === 400) {
      const standardBodyError = await deserializeJson(response);

      throw new MonoCloudOPError(
        standardBodyError.error ?? 'device_token_failed',
        standardBodyError.error_description ?? 'Device code token grant failed'
      );
    }

    if (response.status !== 200) {
      throw new MonoCloudHttpError(
        `Error while performing token grant. Unexpected status code: ${response.status}`
      );
    }

    return await deserializeJson<Tokens>(response);
  }
}
