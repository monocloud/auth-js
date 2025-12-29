import { createRemoteJWKSet, JWTPayload, jwtVerify } from 'jose';
import {
  ensureLeadingSlash,
  findToken,
  getBoolean,
  isAbsoluteUrl,
  isPresent,
  isSameHost,
  now,
  parseSpaceSeparated,
  parseSpaceSeparatedSet,
  setsEqual,
} from '@monocloud/auth-core/internal';
import {
  generateNonce,
  generatePKCE,
  generateState,
  isUserInGroup,
  mergeArrays,
  parseCallbackParams,
} from '@monocloud/auth-core/utils';
import type {
  Authenticators,
  AuthorizationParams,
  DisplayOptions,
  IssuerMetadata,
  MonoCloudSession,
  Prompt,
} from '@monocloud/auth-core';
import {
  MonoCloudOidcClient,
  MonoCloudOPError,
  MonoCloudValidationError,
} from '@monocloud/auth-core';
import { MonoCloudSessionService } from './monocloud-session-service';
import { MonoCloudStateService } from './monocloud-state-service';
import { getOptions } from './options/get-options';
import {
  ApplicationState,
  CallbackOptions,
  GetTokensOptions,
  MonoCloudOptions,
  MonoCloudOptionsBase,
  MonoCloudState,
  MonoCloudTokens,
  SignInOptions,
  SignOutOptions,
  UserInfoOptions,
} from './types';
import {
  IMonoCloudCookieRequest,
  IMonoCloudCookieResponse,
  MonoCloudRequest,
  MonoCloudResponse,
} from './types/internal';
import {
  callbackOptionsSchema,
  getTokensOptionsSchema,
  resourceValidationSchema,
  scopesValidationSchema,
  signInOptionsSchema,
  signOutOptionsSchema,
  userInfoOptionsSchema,
} from './options/validation';
import dbug, { Debugger } from 'debug';

export class MonoCloudCoreClient {
  public readonly oidcClient: MonoCloudOidcClient;

  private readonly options: MonoCloudOptionsBase;

  private readonly stateService: MonoCloudStateService;

  private readonly sessionService: MonoCloudSessionService;

  private readonly debug: Debugger;

  private optionsValidated = false;

  constructor(partialOptions?: MonoCloudOptions) {
    this.options = getOptions(partialOptions, false);
    this.oidcClient = new MonoCloudOidcClient(
      this.options.tenantDomain,
      this.options.clientId,
      {
        clientSecret: this.options.clientSecret,
        idTokenSigningAlgorithm: this.options.idTokenSigningAlg,
      }
    );
    this.debug = dbug(this.options.debugger);
    this.stateService = new MonoCloudStateService(this.options);
    this.sessionService = new MonoCloudSessionService(this.options);

    /* v8 ignore next -- @preserve */
    if (process.env.DEBUG && !this.debug.enabled) {
      dbug.enable(process.env.DEBUG);
    }

    this.debug('Debug logging enabled.');
  }

  /**
   * Initiates the sign-in flow by redirecting the user to the MonoCloud authorization endpoint.
   *
   * This method handles scope and resource merging, state generation (nonce, state, PKCE),
   * and Constructing the final authorization URL.
   *
   * @param request - MonoCloud request object.
   * @param response - MonoCloud response object.
   * @param signInOptions - Configuration to customize the sign-in behavior.
   * @returns A promise that resolves when the callback processing and redirection are complete.
   *
   * @throws {@link MonoCloudValidationError} When validation of parameters or state fails.
   */
  async signIn(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    signInOptions?: SignInOptions
  ): Promise<any> {
    this.debug('Starting sign-in handler');
    try {
      this.validateOptions();

      const { method } = await request.getRawRequest();

      if (method.toLowerCase() !== 'get') {
        response.methodNotAllowed();
        return response.done();
      }

      const indicatorResource = this.options.resources
        ?.map(x => x.resource)
        .filter(x => !!x)
        .reduce((acc, x) => `${acc} ${x}`, '');
      const indicatorScopes = this.options.resources
        ?.map(x => x.scopes)
        .filter(x => !!x)
        .reduce((acc, x) => `${acc} ${x}`, '');

      const mergedScopes = mergeArrays(
        parseSpaceSeparated(signInOptions?.authParams?.scopes),
        parseSpaceSeparated(this.options.defaultAuthParams.scopes),
        parseSpaceSeparated(indicatorScopes)
      ) ?? ['openid'];

      const mergedResources = mergeArrays(
        parseSpaceSeparated(signInOptions?.authParams?.resource),
        parseSpaceSeparated(this.options.defaultAuthParams.resource),
        parseSpaceSeparated(indicatorResource)
      );

      // Merge the sign-in options and the default options
      const opt = {
        ...(signInOptions ?? {}),
        authParams: {
          ...this.options.defaultAuthParams,
          ...signInOptions?.authParams,
          scopes: mergedScopes.join(' '),
          acrValues: mergeArrays(
            signInOptions?.authParams?.acrValues,
            this.options.defaultAuthParams.acrValues
          ),
          resource: mergedResources?.join(' '),
        },
      };

      let appState: ApplicationState = {};

      // Set the application state if the onSetApplicationState function is set
      if (this.options.onSetApplicationState) {
        appState = await this.options.onSetApplicationState(request);

        // Validate the custom sign-in state
        if (
          appState === null ||
          appState === undefined ||
          typeof appState !== 'object' ||
          Array.isArray(appState)
        ) {
          throw new MonoCloudValidationError(
            'Invalid Application State. Expected state to be an object'
          );
        }
      }

      const query = this.options.allowQueryParamOverrides
        ? {
            returnUrl: request.getQuery('return_url') as string,
            authenticatorHint: request.getQuery(
              'authenticator_hint'
            ) as Authenticators,
            scope: request.getQuery('scope') as string,
            resource: request.getQuery('resource') as string,
            display: request.getQuery('display') as DisplayOptions,
            uiLocales: request.getQuery('ui_locales') as string,
            acrValues: request.getQuery('acr_values') as string,
            loginHint: request.getQuery('login_hint') as string,
            prompt: request.getQuery('prompt') as Prompt,
            maxAge: parseInt(request.getQuery('max_age') as string, 10),
          }
        : {};

      // Set the return url if passed down
      const retUrl = query.returnUrl ?? opt.returnUrl;
      if (
        typeof retUrl === 'string' &&
        retUrl &&
        (!isAbsoluteUrl(retUrl) || isSameHost(this.options.appUrl, retUrl))
      ) {
        opt.returnUrl = retUrl;
      }

      // Validate the options
      const { error } = signInOptionsSchema.validate(opt, { abortEarly: true });

      if (error) {
        throw new MonoCloudValidationError(error.details[0].message);
      }

      // Generate the state, nonce & code verifier
      const state = generateState();
      const nonce = generateNonce();
      const { codeChallenge, codeVerifier } = await generatePKCE();

      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      if (!isNaN(query.maxAge!)) {
        opt.authParams.maxAge = query.maxAge;
      }

      // Ensure that return to is present, if not then use the base url as the return to
      const returnUrl = encodeURIComponent(
        opt.returnUrl ?? this.options.appUrl
      );

      const redirectUrl = `${this.options.appUrl}${ensureLeadingSlash(this.options.routes.callback)}`;

      // Create the Authorization Parameters
      let params: AuthorizationParams = {
        redirectUri: redirectUrl,
        ...opt.authParams,
        nonce,
        state,
        codeChallenge,
      };

      // Set the Authenticator if passed down
      const authenticatorHint =
        query.authenticatorHint ?? opt.authParams.authenticatorHint;
      if (typeof authenticatorHint === 'string' && authenticatorHint) {
        params.authenticatorHint = authenticatorHint;
      }

      const scopes =
        (typeof query.scope === 'string' ? query.scope : undefined) ??
        opt.authParams.scopes;

      if (scopes) {
        const { error: e } = scopesValidationSchema.validate(scopes, {
          abortEarly: true,
        });

        if (!e) {
          params.scopes = scopes;
        }
      }

      const resource =
        (typeof query.resource === 'string' ? query.resource : undefined) ??
        opt.authParams.resource;

      // Set the resources mode if passed down
      if (resource) {
        const { error: e } = resourceValidationSchema.validate(resource, {
          abortEarly: true,
        });

        if (!e) {
          params.resource = resource;
        }
      }

      // Set the display if passed down
      const display = query.display ?? opt.authParams.display;
      if (typeof display === 'string' && display) {
        params.display = display as unknown as DisplayOptions;
      }

      // Set the ui locales if passed down
      const uiLocales = query.uiLocales ?? opt.authParams.uiLocales;
      if (typeof uiLocales === 'string' && uiLocales) {
        params.uiLocales = uiLocales;
      }

      // Set the acr values if passed down
      const acrValues = query.acrValues ?? opt.authParams.acrValues;
      if (typeof acrValues === 'string' && acrValues) {
        params.acrValues = acrValues
          .split(' ')
          .map(x => x.trim())
          .filter(x => x !== '');
      }

      // Set the login hint if passed down
      const loginHint = query.loginHint ?? opt.authParams.loginHint;
      if (typeof loginHint === 'string' && loginHint) {
        params.loginHint = loginHint;
      }

      // Set the prompt if passed down
      let prompt: string | undefined;
      if (typeof query.prompt === 'string') {
        prompt = query.prompt;
      } else {
        prompt = opt.register ? 'create' : opt.authParams.prompt;
      }

      if (prompt) {
        params.prompt = prompt as Prompt;
      }

      /* v8 ignore next -- @preserve */
      if (!params.scopes || params.scopes.length < 0) {
        throw new MonoCloudValidationError(
          'Scopes are required for signing in'
        );
      }

      // Generate the monocloud state
      const monoCloudState: MonoCloudState = {
        returnUrl,
        state,
        nonce,
        codeVerifier,
        maxAge: opt.authParams.maxAge,
        appState: JSON.stringify(appState),
        resource: this.options.defaultAuthParams.resource,
        scopes: params.scopes,
      };

      if (this.options.usePar) {
        const { request_uri } =
          await this.oidcClient.pushedAuthorizationRequest(params);

        params = {
          requestUri: request_uri,
        };
      }

      // Create authorize url
      const authUrl = await this.oidcClient.authorizationUrl(params);

      // Set the state cookie
      await this.stateService.setState(
        response,
        monoCloudState,
        params.responseMode === 'form_post' ? 'none' : undefined
      );
      // Redirect to authorize url
      response.redirect(authUrl, 302);
    } catch (error) {
      if (typeof signInOptions?.onError === 'function') {
        return signInOptions.onError(error as Error);
      } else {
        this.handleCatchAll(error as Error, response);
      }
    }

    return response.done();
  }

  /**
   * Handles the OpenID callback after the user authenticates with MonoCloud.
   *
   * Processes the authorization code, validates the state and nonce, exchanges the code for tokens,
   * initializes the user session, and performs the final redirect to the application's return URL.
   *
   * @param request - MonoCloud request object.
   * @param response - MonoCloud response object.
   * @param callbackOptions - Optional configuration for the callback handler.
   * @returns A promise that resolves when the callback processing and redirection are complete.
   *
   * @throws {@link MonoCloudValidationError} If the state is mismatched or tokens are invalid.
   */
  async callback(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    callbackOptions?: CallbackOptions
  ): Promise<any> {
    this.debug('Starting callback handler');

    try {
      this.validateOptions();

      const { method, url, body } = await request.getRawRequest();

      if (method.toLowerCase() !== 'get' && method.toLowerCase() !== 'post') {
        response.methodNotAllowed();
        return response.done();
      }

      // Validate the callback Options
      if (callbackOptions) {
        const { error } = callbackOptionsSchema.validate(callbackOptions, {
          abortEarly: true,
        });

        if (error) {
          throw new MonoCloudValidationError(error.details[0].message);
        }
      }

      // Get the state value
      const monoCloudState = await this.stateService.getState(
        request,
        response
      );

      // Handle invalid state
      if (!monoCloudState) {
        throw new MonoCloudValidationError('Invalid Authentication State');
      }

      let fullUrl = url;

      // check if the url is a relative url
      if (!isAbsoluteUrl(url)) {
        fullUrl = `${this.options.appUrl}${ensureLeadingSlash(url)}`;
      }

      // Get the search parameters or the body
      const payload =
        method.toLowerCase() === 'post'
          ? new URLSearchParams(body)
          : new URL(fullUrl).searchParams;

      // Get the parameters returned from the server
      const callbackParams = parseCallbackParams(payload);

      if (callbackParams.state !== monoCloudState.state) {
        throw new MonoCloudValidationError('Invalid state');
      }

      if (isPresent(callbackParams.error)) {
        throw new MonoCloudOPError(
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          callbackParams.error!,
          callbackParams.errorDescription
        );
      }

      // Get the redirect Url to be validated
      const redirectUri =
        callbackOptions?.redirectUri ??
        `${this.options.appUrl}${ensureLeadingSlash(this.options.routes.callback)}`;

      if (!callbackParams.code) {
        throw new MonoCloudValidationError(
          'Authorization code not found in callback params'
        );
      }

      // Parse the client state
      const appState: ApplicationState = JSON.parse(monoCloudState.appState);

      const session = await this.oidcClient.authenticate(
        callbackParams.code,
        redirectUri,
        monoCloudState.scopes,
        monoCloudState.resource,
        {
          codeVerifier: monoCloudState.codeVerifier,
          validateIdToken: true,
          idTokenClockSkew: this.options.clockSkew,
          idTokenNonce: monoCloudState.nonce,
          idTokenMaxAge: monoCloudState.maxAge,
          idTokenClockTolerance: 5,
          fetchUserInfo: callbackOptions?.userInfo ?? this.options.userInfo,
          filteredIdTokenClaims: this.options.filteredIdTokenClaims,
          onSessionCreating: async (s, i, u) =>
            await this.options.onSessionCreating?.(s, i, u, appState),
        }
      );

      // Set the user session
      await this.sessionService.setSession(request, response, session);

      // Return to base url if no return url was set
      if (!monoCloudState.returnUrl) {
        response.redirect(this.options.appUrl);
        return response.done();
      }

      // Return to a valid return to url
      try {
        const decodedUrl = decodeURIComponent(monoCloudState.returnUrl);

        if (!isAbsoluteUrl(decodedUrl)) {
          response.redirect(
            `${this.options.appUrl}${ensureLeadingSlash(decodedUrl)}`
          );
          return response.done();
        }

        if (isSameHost(this.options.appUrl, decodedUrl)) {
          response.redirect(decodedUrl);
          return response.done();
        }
        /* c8 ignore start */
      } catch {
        // do nothing
      }
      /* c8 ignore stop */

      response.redirect(this.options.appUrl);
    } catch (error) {
      if (typeof callbackOptions?.onError === 'function') {
        return callbackOptions.onError(error as Error);
      } else {
        this.handleCatchAll(error as Error, response);
      }
    }

    return response.done();
  }

  /**
   * Retrieves user information, optionally refetching fresh data from the UserInfo endpoint.
   *
   * @param request - MonoCloud request object.
   * @param response - MonoCloud response object.
   * @param userinfoOptions - Configuration to control refetching and error handling.
   * @returns A promise that resolves with the user information sent as a JSON response.
   *
   * @remarks
   * If `refresh` is true, the session is updated with fresh claims from the identity provider.
   */
  async userInfo(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    userinfoOptions?: UserInfoOptions
  ): Promise<any> {
    this.debug('Starting userinfo handler');

    try {
      this.validateOptions();

      const { method } = await request.getRawRequest();

      if (method.toLowerCase() !== 'get') {
        response.methodNotAllowed();
        return response.done();
      }

      // Validate the User Info options
      if (userinfoOptions) {
        const { error } = userInfoOptionsSchema.validate(userinfoOptions, {
          abortEarly: true,
        });

        if (error) {
          throw new MonoCloudValidationError(error.details[0].message);
        }
      }

      const query = this.options.allowQueryParamOverrides
        ? { refresh: getBoolean(request.getQuery('refresh') as string) }
        : {};

      const refetchUserInfo =
        query.refresh ??
        userinfoOptions?.refresh ??
        this.options.refetchUserInfo;

      // Get the user session
      const session = await this.sessionService.getSession(
        request,
        response,
        !refetchUserInfo
      );

      // Handle no session
      if (!session) {
        response.setNoCache();
        response.noContent();
        return response.done();
      }

      const defaultToken = findToken(
        session.accessTokens,
        this.options.defaultAuthParams.resource,
        session.authorizedScopes
      );

      // If refetch is false then return the session
      if (!refetchUserInfo || !defaultToken) {
        response.sendJson(session.user);
        return response.done();
      }

      // Get the new session
      const newSession = await this.oidcClient.refetchUserInfo(
        defaultToken,
        session,
        {
          onSessionCreating: this.options.onSessionCreating?.bind(this),
        }
      );

      // Update the session containing the new claims
      const updated = await this.sessionService.updateSession(
        request,
        response,
        newSession
      );

      // Handle session was not updated successfully
      if (!updated) {
        response.setNoCache();
        response.noContent();
        return response.done();
      }

      // Return the Claims
      response.sendJson(session.user);
    } catch (error) {
      if (typeof userinfoOptions?.onError === 'function') {
        return userinfoOptions.onError(error as Error);
      } else {
        this.handleCatchAll(error as Error, response);
      }
    }

    return response.done();
  }

  /**
   * Initiates the sign-out flow, destroying the local session and optionally performing federated sign-out.
   *
   * @param request - MonoCloud request object.
   * @param response - MonoCloud response object.
   * @param signOutOptions - Configuration for post-logout behavior and federated sign-out.
   *
   * @returns A promise that resolves when the sign-out redirection is initiated.
   */
  async signOut(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    signOutOptions?: SignOutOptions
  ): Promise<any> {
    this.debug('Starting sign-out handler');

    try {
      this.validateOptions();

      const { method } = await request.getRawRequest();

      if (method.toLowerCase() !== 'get') {
        response.methodNotAllowed();
        return response.done();
      }

      // Validate the sign-out options
      if (signOutOptions) {
        const { error } = signOutOptionsSchema.validate(signOutOptions, {
          abortEarly: true,
        });

        if (error) {
          throw new MonoCloudValidationError(error.details[0].message);
        }
      }

      const query = this.options.allowQueryParamOverrides
        ? {
            postLogoutUrl: request.getQuery('post_logout_url') as string,
            federated: getBoolean(request.getQuery('federated') as string),
          }
        : {};

      // Build the return to url
      let returnUrl =
        this.options.postLogoutRedirectUri ??
        signOutOptions?.postLogoutRedirectUri ??
        this.options.appUrl;

      // Set the return url if passed down
      if (query.postLogoutUrl) {
        const { error } = signOutOptionsSchema.validate({
          postLogoutRedirectUri: query.postLogoutUrl,
        });

        if (!error) {
          returnUrl = query.postLogoutUrl;
        }
      }

      // Ensure the return to is an absolute one
      if (!isAbsoluteUrl(returnUrl)) {
        returnUrl = `${this.options.appUrl}${ensureLeadingSlash(returnUrl)}`;
      }

      // Get the current session
      const session = await this.sessionService.getSession(
        request,
        response,
        false
      );

      // Redirect to return url if session doesn't exist
      if (!session) {
        response.redirect(returnUrl);
        return response.done();
      }

      await this.sessionService.removeSession(request, response);

      // Handle Federated Sign Out
      const isFederatedSignOut =
        query.federated ??
        signOutOptions?.federatedSignOut ??
        this.options.federatedSignOut;

      if (!isFederatedSignOut) {
        response.redirect(returnUrl);
        return response.done();
      }

      // Build the end session Url
      const url = await this.oidcClient.endSessionUrl({
        idToken: session.idToken,
        postLogoutRedirectUri: returnUrl,
        state: signOutOptions?.state,
      });

      // Redirect the user to the end session endpoint
      response.redirect(url);
    } catch (error) {
      if (typeof signOutOptions?.onError === 'function') {
        return signOutOptions.onError(error as Error);
      } else {
        this.handleCatchAll(error as Error, response);
      }
    }

    return response.done();
  }

  /**
   * Handles Back-Channel Logout notifications from the identity provider.
   *
   * Validates the Logout Token and triggers the `onBackChannelLogout` callback defined in options.
   *
   * @param request - MonoCloud request object.
   * @param response - MonoCloud response object.
   *
   * @returns A promise that resolves when the logout notification has been processed.
   *
   * @throws {@link MonoCloudValidationError} If the logout token is missing or invalid.
   */
  async backChannelLogout(
    request: MonoCloudRequest,
    response: MonoCloudResponse
  ): Promise<any> {
    this.debug('Starting back-channel logout handler');

    try {
      this.validateOptions();

      response.setNoCache();

      if (!this.options.onBackChannelLogout) {
        response.notFound();
        return response.done();
      }

      const { method, body } = await request.getRawRequest();

      if (method.toLowerCase() !== 'post') {
        response.methodNotAllowed();
        return response.done();
      }

      const params = new URLSearchParams(body);
      const logoutToken = params.get('logout_token');

      if (!logoutToken) {
        throw new MonoCloudValidationError('Missing Logout Token');
      }

      const metadata = await this.oidcClient.getMetadata();

      const { sid, sub } = await this.verifyLogoutToken(logoutToken, metadata);

      await this.options.onBackChannelLogout(sub, sid as any);

      response.noContent();
    } catch (error) {
      this.handleCatchAll(error as Error, response);
    }

    return response.done();
  }

  /**
   * Checks if the current request has an active and authenticated session.
   *
   * @param request - MonoCloud cookie request object.
   * @param response - MonoCloud cookie response object.
   *
   * @returns `true` if a valid session with user data exists, `false` otherwise.
   *
   */
  async isAuthenticated(
    request: IMonoCloudCookieRequest,
    response: IMonoCloudCookieResponse
  ): Promise<boolean> {
    // Get the session
    const session = await this.sessionService.getSession(request, response);

    // Return true if the session exists
    return !!session?.user;
  }

  /**
   * Checks if the current session user belongs to the specified groups.
   *
   * @param request - MonoCloud cookie request object.
   * @param response - MonoCloud cookie response object.
   * @param groups - List of group names or IDs to check.
   * @param groupsClaim - Optional claim name that holds groups. Defaults to "groups".
   * @param matchAll - If `true`, requires membership in all groups; otherwise any one group is sufficient.
   *
   * @returns `true` if the user satisfies the group condition, `false` otherwise.
   */
  async isUserInGroup(
    request: IMonoCloudCookieRequest,
    response: IMonoCloudCookieResponse,
    groups: string[],
    groupsClaim?: string,
    matchAll?: boolean
  ): Promise<boolean> {
    const session = await this.sessionService.getSession(request, response);

    if (!session?.user) {
      return false;
    }

    return isUserInGroup(session.user, groups, groupsClaim, matchAll);
  }

  /**
   * Retrieves the current user's session data.
   *
   * @param request - MonoCloud cookie request object.
   * @param response - MonoCloud cookie response object.
   *
   * @returns Session or `undefined`.
   */
  getSession(
    request: IMonoCloudCookieRequest,
    response: IMonoCloudCookieResponse
  ): Promise<MonoCloudSession | undefined> {
    return this.sessionService.getSession(request, response);
  }

  /**
   * Updates the current user's session with new data.
   *
   * @param request - MonoCloud cookie request object.
   * @param response - MonoCloud cookie response object.
   * @param session - The updated session object to persist.
   */
  async updateSession(
    request: IMonoCloudCookieRequest,
    response: IMonoCloudCookieResponse,
    session: MonoCloudSession
  ): Promise<void> {
    await this.sessionService.updateSession(request, response, session);
  }

  /**
   * Returns a copy of the current client configuration options.
   *
   * @returns A copy of the initialized configuration.
   */
  getOptions(): MonoCloudOptionsBase {
    return { ...this.options };
  }

  /**
   * Destroys the local user session.
   *
   * @param request - MonoCloud cookie request object.
   * @param response - MonoCloud cookie response object.
   *
   * @remarks
   * This does not perform federated sign-out. For identity provider sign-out, use `signOut` handler.
   */
  destroySession(
    request: IMonoCloudCookieRequest,
    response: IMonoCloudCookieResponse
  ): Promise<void> {
    return this.sessionService.removeSession(request, response);
  }

  /**
   * Retrieves active tokens (Access, ID, Refresh), performing a refresh if they are expired or missing.
   *
   * @param request - MonoCloud cookie request object.
   * @param response - MonoCloud cookie response object.
   * @param options - Configuration for token retrieval (force refresh, specific scopes/resources).
   *
   * @returns Fetched tokens
   *
   * @throws {@link MonoCloudValidationError} If the session does not exist or tokens cannot be found/refreshed.
   */
  async getTokens(
    request: IMonoCloudCookieRequest,
    response: IMonoCloudCookieResponse,
    options?: GetTokensOptions
  ): Promise<MonoCloudTokens> {
    // Validate the get tokens options
    if (options) {
      const { error } = getTokensOptionsSchema.validate(options, {
        abortEarly: true,
      });

      if (error) {
        throw new MonoCloudValidationError(error.details[0].message);
      }
    }

    // Get the session
    const session = await this.sessionService.getSession(request, response);

    if (!session) {
      throw new MonoCloudValidationError('Session does not exist');
    }

    let scopes = options?.scopes;

    const resource =
      options?.resource ?? this.options.defaultAuthParams.resource;

    if (isPresent(options?.resource)) {
      if (!isPresent(scopes)) {
        // Check if there is a resource with undefined scope
        const noScopeResource = this.options.resources?.find(
          x =>
            setsEqual(
              parseSpaceSeparatedSet(x.resource),
              parseSpaceSeparatedSet(resource)
            ) && !x.scopes
        );

        // Search for the same resource with scopes defined
        if (!noScopeResource) {
          scopes = this.options.resources?.find(x =>
            setsEqual(
              parseSpaceSeparatedSet(x.resource),
              parseSpaceSeparatedSet(resource)
            )
          )?.scopes;
        }
      }
    }

    const findTokenScopes =
      !isPresent(options?.resource) && !isPresent(scopes)
        ? session.authorizedScopes
        : scopes;

    let token = findToken(session.accessTokens, resource, findTokenScopes);

    const tokenExpired = !!token && token.accessTokenExpiration - 30 < now();

    let { idToken } = session;
    let { refreshToken } = session;

    if (options?.forceRefresh || !token || tokenExpired) {
      const updatedSession = await this.oidcClient.refreshSession(session, {
        fetchUserInfo: options?.refetchUserInfo ?? this.options.refetchUserInfo,
        validateIdToken: true,
        idTokenClockSkew: this.options.clockSkew,
        idTokenClockTolerance: 5,
        refreshGrantOptions: {
          resource,
          scopes,
        },
        filteredIdTokenClaims: this.options.filteredIdTokenClaims,
        onSessionCreating: this.options.onSessionCreating?.bind(this),
      });

      await this.sessionService.updateSession(
        request,
        response,
        updatedSession
      );

      token = findToken(
        updatedSession?.accessTokens,
        resource,
        findTokenScopes
      );

      idToken = updatedSession.idToken;
      refreshToken = updatedSession.refreshToken;
    }

    // Just in case. At this point, the access token should be present
    /* v8 ignore next -- @preserve */
    if (!token) {
      throw new MonoCloudValidationError('Access token not found');
    }

    return {
      ...token,
      idToken,
      refreshToken,
      isExpired: token.accessTokenExpiration - 30 < now(),
    };
  }

  private async verifyLogoutToken(
    token: string,
    metadata: IssuerMetadata
  ): Promise<JWTPayload> {
    const jwks = createRemoteJWKSet(new URL(metadata.jwks_uri));

    const { payload } = await jwtVerify(token, jwks, {
      issuer: metadata.issuer,
      audience: this.options.clientId,
      algorithms: [this.options.idTokenSigningAlg],
      requiredClaims: ['iat'],
    });

    if (
      (!payload.sid && !payload.sub) ||
      payload.nonce ||
      !payload.events ||
      typeof payload.events !== 'object'
    ) {
      throw new MonoCloudValidationError('Invalid logout token');
    }

    const event = (payload.events as any)[
      'http://schemas.openid.net/event/backchannel-logout'
    ];

    if (!event || typeof event !== 'object') {
      throw new MonoCloudValidationError('Invalid logout token');
    }

    return payload;
  }

  private handleCatchAll(error: Error, res: MonoCloudResponse): void {
    // eslint-disable-next-line no-console
    console.error(error);
    res.internalServerError();
  }

  private validateOptions(): void {
    if (!this.optionsValidated) {
      this.optionsValidated = true;
      getOptions(this.options);
    }
  }
}
