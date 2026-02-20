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
 * `MonoCloudJSCoreClient` is the core SDK entry point for integrating MonoCloud authentication into browser-based applications (SPAs) or vanilla JavaScript environments.
 *
 * It provides:
 * - Redirection and popup-based sign-in and sign-out
 * - Session and token management
 * - Automatic PKCE and state validation
 * - Silent and explicit token refreshing
 *
 * ## Initialization
 *
 * ```typescript:src/auth.ts
 * import { MonoCloudJSCoreClient } from '@monocloud/auth-js-core';
 *
 * export const client = new MonoCloudJSCoreClient({
 * tenantDomain: 'your-tenant.monocloud.com',
 * clientId: 'your-client-id',
 * appUrl: 'http://localhost:3000',
 * callbackPath: '/callback',
 * signOutCallbackPath: '/logout'
 * });
 * ```
 *
 * @category Classes
 */
export class MonoCloudJSCoreClient {
  private storage: IStorage;

  /**
   * This is intended for advanced scenarios requiring direct control over the authorization or token flow.
   *
   * @returns Returns the underlying **OIDC client** used for OpenID Connect operations.
   */
  oidcClient: MonoCloudOidcClient;

  private options: MonoCloudJSCoreClientOptions;

  /**
   * Default post-callback behavior:
   * - If `returnUrl` is not set: remove query params from the current URL (no navigation).
   * - If `returnUrl` is set: navigate to `returnUrl` (full page reload).
   *
   * If you use a client-side router, provide a custom `postCallbackFn` to avoid full reload.
   */
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

  /**
   * Optional hook invoked while constructing a new session (e.g., after authenticate/refresh).
   * This is useful for mapping app-specific state into your session or running side effects.
   */
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

  /**
   * Persist the callback state in `sessionStorage` for redirect-based flows.
   * This state is consumed by `processCallback()` and then cleared.
   */
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

  /**
   * Storage key used for persisting the current session.
   * Includes `clientId` and optional `sessionKey` suffix to avoid collisions.
   */
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
   * Initializes a new instance of the MonoCloudJSCoreClient.
   *
   * @example Default Integration
   * ```typescript:src/auth.ts tab="Default Integration" tab-group="constructor"
   * import { MonoCloudJSCoreClient } from '@monocloud/auth-js-core';
   *
   * const client = new MonoCloudJSCoreClient({
   * tenantDomain: 'your-tenant.monocloud.com',
   * clientId: 'your-client-id',
   * appUrl: 'http://localhost:3000',
   * });
   * ```
   *
   * @example Custom Storage & Router
   * ```typescript:src/auth.ts tab="Custom Storage & Router" tab-group="constructor"
   * import { MonoCloudJSCoreClient } from '@monocloud/auth-js-core';
   * import { InMemoryStorage } from './storage';
   * import { router } from './router';
   *
   * const client = new MonoCloudJSCoreClient(
   * options,
   * new InMemoryStorage(),
   * (state) => {
   * // Use router to navigate instead of full page reload
   * router.push(state.returnUrl || '/dashboard');
   * }
   * );
   * ```
   *
   * @param options Configuration options for the client.
   * @param storage Custom storage implementation for session persistence. Defaults to `localStorage`.
   * @param postCallbackFn A callback function executed after a successful sign-in or sign-out. Useful for client-side routing integration.
   * @param onSessionCreating A hook to modify or validate the session during creation.
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
   * Processes the authentication callback.
   *
   * This method must be called on application startup (usually in the entry point or router)
   * to handle the response from the identity provider after a redirect flow.
   *
   * - **Main Window:** Validates the state and code, exchanges them for tokens, and establishes the session.
   * - **Popup/Iframe:** Posts the callback URL back to the parent/opener window to complete the flow.
   *
   * @example Application Entry
   * ```typescript:src/main.ts
   * import { client } from './auth';
   *
   * async function init() {
   * // Process any pending redirect callbacks before rendering
   * await client.processCallback();
   *
   * // Continue mounting the app
   * renderApp();
   * }
   *
   * init();
   * ```
   *
   * @returns A promise that resolves when the callback processing is complete.
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
   * Initiates the sign-in flow.
   *
   * @example Redirect Flow
   * ```typescript:src/app.ts tab="Redirect Flow" tab-group="signIn"
   * document.getElementById('login-btn').addEventListener('click', async () => {
   * // Standard top-level redirect to the authorization server
   * await client.signIn();
   * });
   * ```
   *
   * @example Popup Flow
   * ```typescript:src/app.ts tab="Popup Flow" tab-group="signIn"
   * document.getElementById('login-popup-btn').addEventListener('click', async () => {
   * // Opens a centered popup for authentication
   * await client.signIn({ mode: 'popup' });
   * console.log("User finished popup flow!");
   * });
   * ```
   *
   * @example Sign Up
   * ```typescript:src/app.ts tab="Sign Up" tab-group="signIn"
   * document.getElementById('register-btn').addEventListener('click', async () => {
   * // Forces the identity provider to show the registration/sign-up screen
   * await client.signIn({ signUp: true });
   * });
   * ```
   *
   * @param signInOptions Optional configuration for the sign-in request.
   * @throws {@link MonoCloudJsError} If called from within a popup or iframe.
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
   * Initiates the sign-out flow.
   *
   * Clears the local session and optionally redirects the user to the identity provider to end the session there (Federated Sign-Out).
   *
   * @example Standard Sign Out
   * ```typescript:src/app.ts tab="Redirect Flow" tab-group="signOut"
   * document.getElementById('logout-btn').addEventListener('click', async () => {
   * await client.signOut();
   * });
   * ```
   *
   * @example Popup Sign Out
   * ```typescript:src/app.ts tab="Popup Flow" tab-group="signOut"
   * document.getElementById('logout-popup-btn').addEventListener('click', async () => {
   * // Opens a popup to perform the federated sign-out, keeping the user on the current page
   * await client.signOut({ mode: 'popup' });
   * });
   * ```
   *
   * @param signOutOptions Optional configuration for the sign-out request.
   * @throws {@link MonoCloudJsError} If called from within a popup or iframe.
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
   * Refreshes the user's session.
   *
   * This method can be used to explicitly refresh tokens using various methods:
   * - `silent`: Uses a hidden iframe (requires 3rd party cookies).
   * - `refresh_token`: Uses the Refresh Token Grant (requires `offline_access` scope).
   * - `popup`: Opens a transient popup to refresh the session interactively.
   *
   * @example Silent Refresh (Iframe)
   * ```typescript:src/app.ts tab="Silent (Iframe)" tab-group="refreshSession"
   * await client.refreshSession({ mode: 'silent' });
   * ```
   *
   * @example Refresh Token Grant
   * ```typescript:src/app.ts tab="Refresh Token" tab-group="refreshSession"
   * await client.refreshSession({ mode: 'refresh_token' });
   * ```
   *
   * @param refreshOptions Optional configuration for the refresh flow.
   * @throws {@link MonoCloudValidationError} If the session is invalid or missing required tokens.
   * @throws {@link MonoCloudJsError} If called from within a popup or iframe.
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
   * Refetches the user information from the userinfo endpoint and updates the local session.
   *
   * @example Usage
   * ```typescript:src/app.ts
   * await client.refetchUserInfo();
   * const session = await client.getSession();
   * console.log('Updated user data:', session.user);
   * ```
   *
   * @throws {@link MonoCloudValidationError} If the session is invalid or the default token is missing.
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
   * Retrieves the active tokens for the session.
   *
   * If the tokens are expired or about to expire, this method will attempt to refresh them automatically before returning.
   *
   * @example Get Default Tokens
   * ```typescript:src/app.ts tab="Default Tokens" tab-group="getTokens"
   * const tokens = await client.getTokens();
   * console.log(tokens.accessToken);
   * ```
   *
   * @example Force Refresh
   * ```typescript:src/app.ts tab="Force Refresh" tab-group="getTokens"
   * const tokens = await client.getTokens({ forceRefresh: true });
   * ```
   *
   * @example Specific Resource
   * ```typescript:src/app.ts tab="Specific Resource" tab-group="getTokens"
   * const tokens = await client.getTokens({
   * resource: '[https://api.example.com](https://api.example.com)',
   * scopes: 'read:data'
   * });
   * ```
   *
   * @param options Options to control token retrieval (e.g., force refresh).
   * @returns The active tokens.
   * @throws {@link MonoCloudValidationError} If the session does not exist.
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
   * Retrieves the current session object from local storage.
   *
   * @example Usage
   * ```typescript:src/app.ts
   * const session = await client.getSession();
   * if (session) {
   * console.log('User is logged in:', session.user);
   * }
   * ```
   *
   * @returns The active session or `undefined` if not authenticated.
   */
  async getSession(): Promise<MonoCloudSession | undefined> {
    try {
      return JSON.parse((await this.storage.getItem(this.sessionKey)) ?? '');
    } catch {
      await this.storage.removeItem(this.sessionKey);
      return undefined;
    }
  }

  /**
   * Persist or clear the session in storage.
   *
   * @param session When provided, the session is serialized to storage. When omitted, the session is removed.
   */
  private async setSession(session?: MonoCloudSession): Promise<void> {
    if (!session) {
      await this.storage.removeItem(this.sessionKey);
      return;
    }

    await this.storage.setItem(this.sessionKey, JSON.stringify(session));
  }

  /**
   * Complete a sign-in flow using a callback URL and the saved callback state.
   *
   * Validates:
   * - Callback URL matches configured `redirectUri`
   * - Callback state is present and matches the response (`state`)
   * - Authorization response parameters (success or error)
   * - ID token (optional, depending on configuration and flow)
   *
   * On success, creates/updates the session and invokes the configured post-callback handler.
   *
   * @param callbackUrl Full callback URL received from the OP.
   * @param callbackState State captured when initiating the flow.
   *
   * @throws {@link MonoCloudValidationError} If validation fails.
   * @throws {@link MonoCloudOPError} If the OP returned an error response.
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

    /* v8 ignore next -- @preserve */
    throw new MonoCloudValidationError('Invalid sign in callback');
  }

  /**
   * Complete a sign-out callback.
   *
   * Clears the local session and validates that the callback `state` matches the
   * stored callback state for the initiated sign-out flow.
   *
   * @param callbackUrl Full callback URL received from the OP.
   * @param callbackState State captured when initiating the sign-out flow.
   *
   * @throws {@link MonoCloudValidationError} If callback validation fails.
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

  /**
   * Run an auth request inside a popup window or hidden iframe and wait for the callback URL.
   *
   * This method:
   * - navigates the popup/iframe to the provided authorization URL
   * - waits for a `postMessage` from the popup/iframe containing the callback URL
   * - rejects on timeout or if the user closes the popup
   *
   * It does not parse or validate the callback parameters; the caller does that.
   *
   * @param url Authorization/end-session URL to load in the auth window.
   * @param ref Wrapper around the popup/iframe reference.
   * @returns The callback URL received via `postMessage`.
   *
   * @throws {@link MonoCloudJsError} On timeout or if the user closes the popup.
   */
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

  /**
   * Create a window reference appropriate for the interaction mode.
   *
   * - `popup`  -> opens a popup window
   * - `silent` -> creates a hidden iframe
   * - other modes do not require a window reference
   */
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

  /**
   * Open a centered popup window for interactive authentication.
   *
   * @returns A `Ref` bound to the popup window.
   * @throws {@link MonoCloudJsError} If the browser blocks the popup.
   */
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

  /**
   * Create a hidden iframe for silent authentication (`prompt=none`).
   *
   * @returns A `Ref` bound to the iframe element.
   * @throws {@link MonoCloudJsError} If the environment is cross-origin isolated.
   */
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
