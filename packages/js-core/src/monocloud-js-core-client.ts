import {
  generateNonce,
  generatePKCE,
  generateState,
  mergeArrays,
  parseCallbackParams,
} from '@monocloud/auth-core/utils';
import type {
  AuthorizationParams,
  IdTokenClaims,
  MonoCloudSession,
  ResponseTypes,
  UserinfoResponse,
} from '@monocloud/auth-core';
import {
  ensureLeadingSlash,
  findToken,
  isPresent,
  now,
  parseSpaceSeparated,
  parseSpaceSeparatedSet,
  removeTrailingSlash,
  setsEqual,
} from '@monocloud/auth-core/internal';
import type {
  CallbackState,
  IStorage,
  MonoCloudJSCoreClientOptions,
  PostCallback,
  PostMessageResult,
  RefreshOptions,
  SignInOptions,
  SignOutOptions,
  OnSessionCreating,
  GetTokensOptions,
  MonoCloudTokens,
  InteractionMode,
} from './types';
import { AUTH_CONSTANTS } from './constants';
import { Ref } from './ref';
import { localStorage } from './storage';
import {
  MonoCloudOidcClient,
  MonoCloudOPError,
  MonoCloudValidationError,
} from '@monocloud/auth-core';
import { MonoCloudJsError } from './monocloud-js-error';
import { withLock } from './lock';

/**
 * MonoCloudJSCoreClient manages authentication and session for JavaScript apps that run in the browser.
 *
 * @example Initialize MonoCloudJSCoreClient
 *
 * const monoCloudClient = new MonoCloudJSCoreClient({
 *   domain: 'your-domain.monocloud.com',
 *   clientId: 'your-client-id',
 *   appUrl: 'https://your-app.com',
 *   callbackPath: '/callback',
 *   signOutCallbackPath: '/signout-callback'
 * });
 *
 * // Basic usage
 * await monoCloudClient.signIn();
 * await monoCloudClient.processCallback();
 */
export class MonoCloudJSCoreClient {
  private storage: IStorage;

  /**
   * The underlying OIDC client instance used for low-level OpenID Connect operations.
   *
   * @example
   * // Manually revoke an access token
   * await client.oidcClient.revokeToken(accessToken, 'access_token');
   */
  oidcClient: MonoCloudOidcClient;

  private options: MonoCloudJSCoreClientOptions;

  private postCallbackFn: PostCallback = state => {
    if (!state.returnUrl) {
      const url = new URL(window.location.href);
      url.search = '';
      history.replaceState({}, document.title, url.href);
    } else {
      // eslint-disable-next-line no-console
      console.warn(
        'Warning: The default behavior for return url is to perform a full page reload, which will reset all data if you are using memoryStorage. To integrate with a client-side router, pass a custom postCallback() function during client initialization.'
      );
      window.location.href = state.returnUrl;
    }

    return;
  };

  private onSessionCreating?: OnSessionCreating;

  private get filteredIdTokenClaims(): string[] {
    return (
      this.options.filteredIdTokenClaims ?? [
        ...AUTH_CONSTANTS.FILTERED_ID_TOKEN_CLAIMS,
      ]
    );
  }

  private get authWindowTimeout(): number {
    return (
      this.options.authWindowTimeout ?? AUTH_CONSTANTS.DEFAULT_TIMEOUT_SECONDS
    );
  }

  private get clockSkew(): number {
    return this.options.clockSkew ?? AUTH_CONSTANTS.DEFAULT_CLOCK_SKEW_SECONDS;
  }

  private get clockTolerance(): number {
    return (
      this.options.clockTolerance ??
      AUTH_CONSTANTS.DEFAULT_CLOCK_TOLERANCE_SECONDS
    );
  }

  private get fetchUserinfo(): boolean {
    return this.options.fetchUserinfo ?? AUTH_CONSTANTS.DEFAULT_FETCH_USERINFO;
  }

  private get validateIdToken(): boolean {
    return (
      this.options.validateIdToken ?? AUTH_CONSTANTS.DEFAULT_VALIDATE_ID_TOKEN
    );
  }

  private get responseType(): ResponseTypes {
    return this.options.responseType ?? AUTH_CONSTANTS.DEFAULT_RESPONSE_TYPE;
  }

  private get federatedSignOut(): boolean {
    return (
      this.options.federatedSignOut ?? AUTH_CONSTANTS.DEFAULT_FEDERATED_SIGNOUT
    );
  }

  private get redirectUri(): string {
    return `${this.options.appUrl}${this.options.callbackPath ? ensureLeadingSlash(this.options.callbackPath) : '/'}`;
  }

  private get signOutRedirectUri(): string {
    return `${this.options.appUrl}${ensureLeadingSlash(
      this.options.signOutCallbackPath ?? '/'
    )}`;
  }

  private get callbackStateKey(): string {
    return `${AUTH_CONSTANTS.CALLBACK_KEY}.${this.options.clientId}`;
  }

  private get lockKey(): string {
    return `${AUTH_CONSTANTS.LOCK_KEY}.${this.options.clientId}`;
  }

  private set redirectCallbackState(state: CallbackState | undefined) {
    if (!state) {
      window.sessionStorage.removeItem(this.callbackStateKey);
      return;
    }

    window.sessionStorage.setItem(this.callbackStateKey, JSON.stringify(state));
  }

  private get redirectCallbackState(): CallbackState | undefined {
    try {
      const stored = window.sessionStorage.getItem(this.callbackStateKey);

      if (!stored) {
        return undefined;
      }

      return JSON.parse(stored);
    } catch (error) {
      window.sessionStorage.removeItem(this.callbackStateKey);

      // eslint-disable-next-line no-console
      console.error('Unexpected error reading callback state:');

      throw error;
    }
  }

  private get popupWindowWidth(): number {
    return this.options.popupWindowWidth ?? AUTH_CONSTANTS.POPUP_WINDOW_WIDTH;
  }

  private get popupWindowHeight(): number {
    return this.options.popupWindowHeight ?? AUTH_CONSTANTS.POPUP_WINDOW_HEIGHT;
  }

  private get sessionKey(): string {
    return `${AUTH_CONSTANTS.SESSION_KEY}.${this.options.clientId}${this.options.sessionKey ? `.${this.options.sessionKey}` : ''}`;
  }

  private get appOrigin(): string {
    return new URL(this.options.appUrl).origin;
  }

  private get isTopLevel(): boolean {
    return window.top === window;
  }

  private get isSameParent(): boolean {
    return window.parent === window;
  }

  private get hasOpener(): boolean {
    return window.opener !== null;
  }

  private get isIframe(): boolean {
    return !this.isTopLevel && !this.isSameParent && !this.hasOpener;
  }

  private get isPopup(): boolean {
    return this.isTopLevel && this.isSameParent && this.hasOpener;
  }

  private get mainWindow(): boolean {
    return !this.isIframe && !this.isPopup;
  }

  /**
   * Creates a new instance of MonoCloudJSCoreClient.
   *
   * @param {MonoCloudJSCoreClientOptions} options - Configuration options for the client
   * @param {IStorage} [storage=window.localStorage] - Storage for storing session
   * @param {PostCallback} [postCallbackFn] - A function that is executed after a sign in or sign out callback.
   * default `PostCallback` to redirect to the `returnUrl` after a sign in or sign out.
   * **If you have configured a custom `PostCallback` function, this parameter can be ignored.**
   * @example
   * const client = new MonoCloudJSCoreClient({
   *   domain: 'your-domain.monocloud.com',
   *   clientId: 'your-client-id',
   *   appUrl: 'https://your-app.com',
   *   callbackPath: '/callback',
   *   signOutCallbackPath: '/signout-callback'
   *   scopes: ['openid', 'profile', 'email'],
   *   responseType: 'code',
   *   validateIdToken: true,
   *   fetchUserinfo: true,
   *   federatedSignOut: true
   * });
   */
  constructor(
    options: MonoCloudJSCoreClientOptions,
    storage: IStorage = localStorage(),
    postCallbackFn?: PostCallback,
    onSessionCreating?: OnSessionCreating
  ) {
    // eslint-disable-next-line no-param-reassign
    options.appUrl = removeTrailingSlash(options.appUrl);

    this.options = options;
    this.storage = storage;
    if (postCallbackFn) {
      this.postCallbackFn = postCallbackFn;
    }

    this.onSessionCreating = onSessionCreating;

    this.oidcClient = new MonoCloudOidcClient(
      this.options.tenantDomain,
      this.options.clientId,
      {
        clientAuthMethod: this.options.clientAuthMethod,
        clientSecret: this.options.clientSecret,
        idTokenSigningAlgorithm: this.options.idTokenSigningAlgorithm,
        jwksCacheDuration: this.options.jwksCacheDuration,
        metadataCacheDuration: this.options.metadataCacheDuration,
      }
    );
  }

  /**
   * Processes authentication callbacks after a redirect, popup, or silent sign-in/sign-out flow.
   *
   * This method must be called exactly once when the application initializes.
   *
   * - In the main window, it validates and completes sign-in or sign-out callbacks
   *   using the stored callback state.
   *
   * - In popup or iframe contexts, it forwards the callback URL to the parent window
   *   using `postMessage` and performs no validation itself.
   *
   * @example
   *
   * await monoCloudClient.processCallback();
   *
   */
  async processCallback(): Promise<void> {
    const currentUrl = new URL(window.location.href);

    const isSignInPath =
      `${currentUrl.origin}${currentUrl.pathname}` === this.redirectUri;
    const isSignOutPath =
      `${currentUrl.origin}${currentUrl.pathname}` === this.signOutRedirectUri;

    if (this.mainWindow) {
      const callbackState = this.redirectCallbackState;
      this.redirectCallbackState = undefined;

      if (callbackState) {
        if (isSignInPath && !callbackState.signOut) {
          await this.processSignInCallback(window.location.href, callbackState);
        } else if (isSignOutPath && callbackState.signOut) {
          await this.processSignOutCallback(
            window.location.href,
            callbackState
          );
        }
      }
    }

    if (!this.mainWindow && (isSignInPath || isSignOutPath)) {
      const parentWindow = (window.opener ?? window.parent) as Window;

      parentWindow.postMessage(
        {
          source: 'monocloud-auth-js-core',
          url: window.location.href,
        },
        this.appOrigin
      );
    }
  }

  /**
   * Starts the sign in flow
   *
   * @param {SignInOptions} [signInOptions] -  Options to customize sign in.
   *
   * @example
   * // Sign in with redirect
   * await monoCloudClient.signIn();
   *
   * // Sign in with popup
   * await monoCloudClient.signIn({ mode: 'popup' });
   *
   * // Show sign up ui
   * await monoCloudClient.signIn({ signUp: true });
   */
  async signIn(signInOptions?: SignInOptions): Promise<void> {
    if (!this.mainWindow) {
      throw new MonoCloudJsError(
        'Initiating an authentication flow in a popup or iframe is not supported'
      );
    }

    const mode = signInOptions?.mode ?? 'redirect';
    const ref = this.createRef(mode);

    try {
      const { codeChallenge, codeVerifier } = await generatePKCE();
      const state = generateState();
      const nonce = generateNonce();

      const indicatorResource = this.options.resources
        ?.map(x => x.resource)
        .filter(x => !!x)
        .reduce((acc, x) => `${acc} ${x}`, '');
      const indicatorScopes = this.options.resources
        ?.map(x => x.scopes)
        .filter(x => !!x)
        .reduce((acc, x) => `${acc} ${x}`, '');

      const mergedScopes =
        mergeArrays(
          parseSpaceSeparated(signInOptions?.scopes),
          parseSpaceSeparated(this.options.defaultAuthParams?.scopes),
          parseSpaceSeparated(indicatorScopes)
        ) ?? AUTH_CONSTANTS.DEFAULT_SCOPES.split(' ');

      const mergedResources = mergeArrays(
        parseSpaceSeparated(signInOptions?.resource),
        parseSpaceSeparated(this.options.defaultAuthParams?.resource),
        parseSpaceSeparated(indicatorResource)
      );

      const params: AuthorizationParams = {
        uiLocales: signInOptions?.uiLocales,
        authenticatorHint: signInOptions?.authenticatorHint,
        loginHint: signInOptions?.loginHint,
        maxAge: signInOptions?.maxAge,
        responseType: this.responseType,
        scopes: mergedScopes.join(' '),
        codeChallenge,
        codeChallengeMethod: 'S256',
        redirectUri: this.redirectUri,
        state,
        nonce,
        resource: mergedResources?.join(' '),
        prompt: signInOptions?.prompt,
        display: signInOptions?.display,
        acrValues: signInOptions?.acrValues,
      };

      if (signInOptions?.signUp) {
        params.prompt = 'create';
      }

      const url = await this.oidcClient.authorizationUrl(params);

      const callbackState: CallbackState = {
        state,
        codeVerifier,
        nonce,
        maxAge: signInOptions?.maxAge,
        mode,
        returnUrl: signInOptions?.returnUrl,
        appState: signInOptions?.appState,
        scopes: params.scopes,
        resource: this.options.defaultAuthParams?.resource,
      };

      if (mode === 'redirect') {
        this.redirectCallbackState = callbackState;
        window.location.assign(url);
        return;
      }

      /* v8 ignore if -- @preserve */
      if (!ref) {
        throw new MonoCloudJsError('Popup or Iframe creation failed');
      }

      const callbackUrl = await this.authWindow(url, ref);

      await this.processSignInCallback(callbackUrl, callbackState);
    } finally {
      ref?.close();
    }
  }

  /**
   * Signs out the current user and optionally performs a federated sign out.
   *
   * @param {SignOutOptions} [signOutOptions] - Sign out options
   *
   * @example
   * // Basic sign out
   * await monoCloudClient.signOut();
   *
   * // Sign out with popup
   * await monoCloudClient.signOut({ mode: 'popup' });
   *
   * // Sign out with custom redirect URI
   * await monoCloudClient.signOut({
   *   postLogoutRedirectUri: 'https://example.com/logout-complete'
   * });
   */
  async signOut(signOutOptions?: SignOutOptions): Promise<void> {
    if (!this.mainWindow) {
      throw new MonoCloudJsError(
        'Initiating an authentication flow in a popup or iframe is not supported'
      );
    }

    const mode = signOutOptions?.mode ?? 'redirect';
    const ref = this.createRef(mode);

    try {
      const session = await this.getSession();

      this.redirectCallbackState = undefined;

      if (!this.federatedSignOut) {
        await this.setSession();
        return;
      }

      const state = generateState();

      let postLogoutRedirectUri: string | undefined;

      if (this.options.signOutCallbackPath) {
        postLogoutRedirectUri = new URL(
          this.options.signOutCallbackPath,
          this.options.appUrl
        ).toString();
      }

      if (signOutOptions?.postLogoutRedirectUri) {
        ({ postLogoutRedirectUri } = signOutOptions);
      }

      const url = await this.oidcClient.endSessionUrl({
        idToken: session?.idToken,
        postLogoutRedirectUri,
        state,
      });

      const callbackState = {
        mode,
        state: new URL(url).searchParams.get('state') ?? undefined,
        signOut: true,
        returnUrl: signOutOptions?.returnUrl,
      };

      if (mode === 'redirect') {
        await this.setSession();
        this.redirectCallbackState = callbackState;
        window.location.assign(url);
        return;
      }

      /* v8 ignore if -- @preserve */
      if (!ref?.getRef()) {
        throw new MonoCloudJsError('Popup or Iframe creation failed');
      }

      const callbackUrl = await this.authWindow(url, ref);

      await this.processSignOutCallback(callbackUrl, callbackState);
    } finally {
      ref?.close();
    }
  }

  /**
   * Refreshes the current session either using a refresh token, silent authentication or popup.
   *
   * @param {RefreshOptions} [refreshOptions] - Refresh session options.
   *
   * @example
   * // Refresh using refresh token grant
   * await monoCloudClient.refreshSession({
   *   mode: 'refresh_token'
   * });
   *
   * // Silent refresh using prompt=none
   * await monoCloudClient.refreshSession({
   *   mode: 'silent'
   * });
   */
  // eslint-disable-next-line consistent-return
  async refreshSession(refreshOptions?: RefreshOptions): Promise<void> {
    if (!this.mainWindow) {
      throw new MonoCloudJsError(
        'Initiating an authentication flow in a popup or iframe is not supported'
      );
    }

    const mode = refreshOptions?.mode ?? 'silent';

    switch (mode) {
      case 'refresh_token': {
        return await withLock(this.lockKey, async () => {
          const session = await this.getSession();
          if (!session) {
            throw new MonoCloudValidationError(
              'Ensure the user is authenticated before refreshing the session'
            );
          }

          if (!session.refreshToken) {
            throw new MonoCloudValidationError(
              'Refresh token not found. Sign in with offline_access scope to get the refresh token.'
            );
          }

          const updatedSession = await this.oidcClient.refreshSession(session, {
            fetchUserInfo: this.fetchUserinfo,
            idTokenClockSkew: this.clockSkew,
            idTokenClockTolerance: this.clockTolerance,
            validateIdToken: this.validateIdToken,
            refreshGrantOptions: refreshOptions?.refreshGrantOptions,
            filteredIdTokenClaims: this.filteredIdTokenClaims,
            onSessionCreating: this.onSessionCreating,
          });

          return await this.setSession(updatedSession);
        });
      }

      case 'popup':
      case 'silent': {
        const ref = this.createRef(mode);
        try {
          const { codeChallenge, codeVerifier } = await generatePKCE();
          const state = generateState();
          const nonce = generateNonce();

          const indicatorResource = this.options.resources
            ?.map(x => x.resource)
            .filter(x => !!x)
            .reduce((acc, x) => `${acc} ${x}`, '');
          const indicatorScopes = this.options.resources
            ?.map(x => x.scopes)
            .filter(x => !!x)
            .reduce((acc, x) => `${acc} ${x}`, '');

          const mergedScopes =
            mergeArrays(
              parseSpaceSeparated(this.options.defaultAuthParams?.scopes),
              parseSpaceSeparated(indicatorScopes)
            ) ?? AUTH_CONSTANTS.DEFAULT_SCOPES.split(' ');

          const mergedResources = mergeArrays(
            parseSpaceSeparated(this.options.defaultAuthParams?.resource),
            parseSpaceSeparated(indicatorResource)
          );

          const url = await this.oidcClient.authorizationUrl({
            prompt: 'none',
            responseType: this.responseType,
            scopes: mergedScopes.join(' '),
            codeChallenge,
            codeChallengeMethod: 'S256',
            redirectUri: this.redirectUri,
            resource: mergedResources?.join(' '),
            state,
            nonce,
          });

          /* v8 ignore if -- @preserve */
          if (!ref) {
            throw new MonoCloudJsError('Popup or Iframe creation failed');
          }

          const callbackUrl = await this.authWindow(url, ref);

          const callbackState: CallbackState = {
            state,
            codeVerifier,
            nonce,
            mode,
            appState: refreshOptions?.appState,
            scopes: mergedScopes.join(' '),
            resource: this.options.defaultAuthParams?.resource,
          };

          return await this.processSignInCallback(callbackUrl, callbackState);
        } finally {
          ref?.close();
        }
      }
    }
  }

  /**
   * Fetches user details using the access token from the userinfo endpoint and updates the current session.
   *
   * @example
   * // Refetch user information
   * await monoCloudClient.refetchUserInfo();
   */
  async refetchUserInfo(): Promise<void> {
    let session = await this.getSession();

    if (!session) {
      throw new MonoCloudValidationError(
        'Ensure the user is authenticated before refetching userinfo'
      );
    }

    const defaultToken = findToken(
      session.accessTokens,
      this.options.defaultAuthParams?.resource,
      session.authorizedScopes
    );

    if (!defaultToken) {
      throw new MonoCloudValidationError('Default token not found');
    }

    session = await this.oidcClient.refetchUserInfo(defaultToken, session, {
      onSessionCreating: this.onSessionCreating,
    });

    await this.setSession(session);
  }

  /**
   * Retrieves active tokens (Access, ID, Refresh), performing a refresh if they are expired or missing.
   *
   * @param options - Configuration for token retrieval (force refresh, specific scopes/resources).
   *
   * @returns Fetched tokens
   *
   * @example
   *
   * await monoCloudClient.getTokens();
   */
  async getTokens(options?: GetTokensOptions): Promise<MonoCloudTokens> {
    return await withLock(this.lockKey, async () => {
      const session = await this.getSession();

      if (!session) {
        throw new MonoCloudValidationError('Session does not exist');
      }

      let scopes = options?.scopes;

      const resource =
        options?.resource ?? this.options.defaultAuthParams?.resource;

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
          fetchUserInfo: options?.refetchUserInfo,
          validateIdToken: true,
          idTokenClockSkew: this.options.clockSkew,
          idTokenClockTolerance: this.clockTolerance,
          refreshGrantOptions: {
            resource,
            scopes,
          },
          filteredIdTokenClaims: this.options.filteredIdTokenClaims,
          onSessionCreating: this.onSessionCreating,
        });

        await this.setSession(updatedSession);

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
    });
  }

  /**
   * Returns the session of the currently signed in user.
   *
   * @example
   * await monoCloudClient.getSession();
   */
  async getSession(): Promise<MonoCloudSession | undefined> {
    try {
      return JSON.parse((await this.storage.getItem(this.sessionKey)) ?? '');
    } catch {
      await this.storage.removeItem(this.sessionKey);
      return undefined;
    }
  }

  private async setSession(session?: MonoCloudSession): Promise<void> {
    if (!session) {
      await this.storage.removeItem(this.sessionKey);
      return;
    }

    await this.storage.setItem(this.sessionKey, JSON.stringify(session));
  }

  /**
   * Processes a completed sign-in callback URL.
   *
   * This method validates:
   * - Callback URL and path
   * - Callback state
   * - Authorization response parameters
   *
   * It creates and stores a new session on success and invokes the configured
   * post-callback handler.
   *
   * @throws {MonoCloudValidationError} if validation fails
   * @throws {MonoCloudOPError} if the authorization server returns an error
   */
  private async processSignInCallback(
    callbackUrl: string,
    callbackState: CallbackState
  ): Promise<void> {
    const url = new URL(callbackUrl);

    if (this.redirectUri !== `${url.origin}${url.pathname}`) {
      throw new MonoCloudValidationError('Incorrect callback url');
    }

    if (callbackState.signOut) {
      throw new MonoCloudValidationError('Incorrect callback state');
    }

    if (!isPresent(callbackState.scopes)) {
      throw new MonoCloudValidationError('Scopes missing from callback state');
    }

    const callbackParams = parseCallbackParams(
      this.responseType === 'code' ? url.search : url.hash
    );

    if (
      !callbackParams.accessToken &&
      !callbackParams.code &&
      !callbackParams.idToken &&
      !callbackParams.error
    ) {
      throw new MonoCloudValidationError('No parameters found in callback');
    }

    if (callbackState.state && callbackParams.state !== callbackState.state) {
      throw new MonoCloudValidationError('Sign in callback states mismatch');
    }

    if (callbackParams.error) {
      throw new MonoCloudOPError(
        callbackParams.error,
        callbackParams.errorDescription
      );
    }

    // Implicit/Hybrid
    if (
      !callbackParams.code &&
      (callbackParams.idToken || callbackParams.accessToken)
    ) {
      let idTokenClaims = {} as IdTokenClaims;
      if (callbackParams.idToken) {
        if (this.validateIdToken) {
          const jwks = await this.oidcClient.getJwks();
          idTokenClaims = await this.oidcClient.validateIdToken(
            callbackParams.idToken,
            jwks.keys,
            this.clockSkew,
            this.clockTolerance,
            callbackState.maxAge,
            callbackState.nonce
          );
        } else {
          idTokenClaims = MonoCloudOidcClient.decodeJwt(callbackParams.idToken);
        }
      }

      let userinfo = {} as unknown as UserinfoResponse;

      if (
        callbackParams.accessToken &&
        this.fetchUserinfo &&
        callbackParams.scope?.includes('openid')
      ) {
        userinfo = await this.oidcClient.userinfo(callbackParams.accessToken);
      }

      const session: MonoCloudSession = {
        user: {
          ...idTokenClaims,
          ...userinfo,
        },
        idToken: callbackParams.idToken,
        accessTokenExpiration: callbackParams.expiresIn
          ? now() + callbackParams.expiresIn
          : undefined,
      };

      if (callbackParams.accessToken) {
        session.accessTokens = [
          {
            accessToken: callbackParams.accessToken,
            scopes: callbackParams.scope ?? '',
            accessTokenExpiration: 1,
          },
        ];
      }

      await this.setSession(session);

      await this.postCallbackFn({
        type: 'signIn',
        returnUrl: callbackState.returnUrl,
        mode: callbackState.mode,
      });
      return;
    }

    // Authorization Code
    if (callbackParams.code) {
      const session = await this.oidcClient.authenticate(
        callbackParams.code,
        this.redirectUri,
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        callbackState.scopes!,
        this.options.defaultAuthParams?.resource,
        {
          fetchUserInfo: this.fetchUserinfo,
          validateIdToken: this.validateIdToken,
          idTokenNonce: callbackState.nonce,
          codeVerifier: callbackState.codeVerifier,
          idTokenMaxAge: callbackState.maxAge,
          idTokenClockSkew: this.clockSkew,
          idTokenClockTolerance: this.clockTolerance,
          filteredIdTokenClaims: this.filteredIdTokenClaims,
          onSessionCreating: async (s, i, u) => {
            await this.onSessionCreating?.(s, i, u, callbackState.appState);
          },
        }
      );

      await this.setSession(session);

      await this.postCallbackFn({
        type: 'signIn',
        returnUrl: callbackState.returnUrl,
        mode: callbackState.mode,
      });

      return;
    }

    throw new MonoCloudValidationError('Invalid sign in callback');
  }

  /**
   * Opens a popup window or silent iframe to perform an authentication request
   * and waits for the callback URL to be returned via postMessage.
   *
   * This method does not parse or validate authentication responses.
   * It only returns the callback URL to the caller.
   */
  private async processSignOutCallback(
    callbackUrl: string,
    callbackState: CallbackState
  ): Promise<void> {
    await this.setSession();
    const url = new URL(callbackUrl);

    if ((this.options.signOutCallbackPath ?? '/') !== url.pathname) {
      throw new MonoCloudValidationError('Incorrect callback url');
    }

    if (!callbackState.signOut) {
      throw new MonoCloudValidationError('Incorrect callback state');
    }

    const callbackParams = parseCallbackParams(url.search);

    if (callbackParams.state !== callbackState.state) {
      throw new MonoCloudValidationError('Sign out states mismatch');
    }

    await this.postCallbackFn({
      type: 'signOut',
      returnUrl: callbackState.returnUrl,
      mode: callbackState.mode as InteractionMode,
    });
  }

  private async authWindow(url: string, ref: Ref): Promise<string> {
    ref.setUrl(url);
    return await new Promise<string>((resolve, reject) => {
      const controller = new AbortController();

      // eslint-disable-next-line prefer-const
      let timeoutTimer: number | undefined;
      // eslint-disable-next-line prefer-const
      let intervalTimer: number | undefined;

      const abort = (): void => {
        controller.abort();
        clearInterval(intervalTimer);
        clearTimeout(timeoutTimer);
        ref.close();
      };

      const listener = (e: MessageEvent<PostMessageResult>): void => {
        if (e.origin !== this.appOrigin) {
          return;
        }

        if (typeof e.data !== 'object' || !isPresent(e.data.url)) {
          return;
        }

        if (e.source !== ref.getWindow()) {
          return;
        }

        if (e.data.source !== 'monocloud-auth-js-core') {
          return;
        }

        if (e.data.url) {
          abort();
          resolve(e.data.url);
        }
      };

      timeoutTimer = setTimeout(() => {
        abort();
        reject(new MonoCloudJsError('Window timed out'));
      }, this.authWindowTimeout * 1000) as unknown as number;

      intervalTimer = setInterval(() => {
        /* v8 ignore else -- @preserve */
        if (ref.getRef<Window>()?.closed) {
          abort();
          reject(new MonoCloudJsError('Window closed by user'));
        }
      }, 100) as unknown as number;

      window.addEventListener('message', listener, {
        signal: controller.signal,
      });
    });
  }

  private createRef(
    mode: 'popup' | 'silent' | 'redirect' | 'refresh_token'
  ): Ref | undefined {
    switch (mode) {
      case 'popup':
        return this.createPopup();

      case 'silent':
        return this.createIframe();

      default:
        return undefined;
    }
  }

  private createPopup(): Ref {
    const { screenLeft, screenTop } = window;

    const screenWidth = window.innerWidth;
    const screenHeight = window.innerHeight;

    const windowWidth = this.popupWindowWidth;
    const windowHeight = this.popupWindowHeight;

    const defaultLeft = screenLeft + (screenWidth - windowWidth) / 2;
    const defaultTop = screenTop + (screenHeight - windowHeight) / 2;

    const maxLeft = screenLeft + (screenWidth - windowWidth);
    const maxTop = screenTop + (screenHeight - windowHeight);

    const width = Math.min(windowWidth, screenWidth);
    const height = Math.min(windowHeight, screenHeight);
    const left = Math.max(0, Math.min(defaultLeft, maxLeft));
    const top = Math.max(0, Math.min(defaultTop, maxTop));

    const popupWindow =
      window.open(
        'about:blank',
        'mc.popup',
        `width=${width},height=${height},top=${top},left=${left}`
      ) ?? undefined;

    const ref = new Ref('popup', popupWindow);
    if (!ref.getRef()) {
      throw new MonoCloudJsError('Could not open popup');
    }

    return ref;
  }

  private createIframe(): Ref {
    if (window.crossOriginIsolated) {
      throw new MonoCloudJsError('Isolated Cross-Origin. Cannot create iframe');
    }

    const iframe = window.document.createElement('iframe');

    iframe.setAttribute('width', '0');
    iframe.setAttribute('height', '0');
    iframe.style.display = 'none';

    const ref = new Ref('silent', iframe);
    window.document.body.appendChild(ref.getRef<HTMLIFrameElement>());
    return ref;
  }
}
