import {
  generateNonce,
  generatePKCE,
  generateState,
  mergeArrays,
  parseCallbackParams,
} from '@monocloud/auth-core/utils';
import type {
  AccessToken,
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
  MonoCloudWebJSClientOptions,
  PostCallback,
  PostMessageResult,
  RefreshOptions,
  SignInOptions,
  SignInSilentOptions,
  SignOutOptions,
  OnSessionCreating,
  GetTokensOptions,
  MonoCloudTokens,
  InteractionMode,
} from './types';
import { AUTH_CONSTANTS } from './constants';
import { Ref } from './ref';
import { LocalStorage } from './storage';
import {
  MonoCloudOidcClient,
  MonoCloudOPError,
  MonoCloudValidationError,
} from '@monocloud/auth-core';
import { MonoCloudJsError } from './monocloud-js-error';
import { withDedupedLock } from './lock';

/**
 * `MonoCloudWebJSClient` is the core SDK entry point for integrating MonoCloud
 * authentication into single-page applications (SPAs) and other browser-based
 * JavaScript environments.
 *
 * Features:
 * - Redirect and popup sign-in / sign-out flows.
 * - Silent sign-in via a hidden iframe (`prompt=none`) for restoring SSO sessions at app bootstrap.
 * - Refresh Token Grant based session refreshing.
 * - Session and token storage with pluggable storage adapters.
 * - Automatic PKCE, state, and nonce generation and validation.
 *
 * ## Initialization
 *
 * ```typescript:src/auth.ts
 * import { MonoCloudWebJSClient } from '@monocloud/auth-web-js';
 *
 * export const client = new MonoCloudWebJSClient({
 *   tenantDomain: 'https://your-tenant.us.monocloud.com',
 *   clientId: 'your-client-id',
 *   appUrl: 'http://localhost:3000',
 *   callbackPath: '/callback',
 *   signOutCallbackPath: '/logout',
 * });
 * ```
 *
 * @category Classes
 */
export class MonoCloudWebJSClient {
  private readonly storage: IStorage;

  /**
   * Underlying OpenID Connect client used for advanced authorization and token operations.
   *
   * Use this when you need lower-level access to OIDC protocol operations not directly exposed by the SDK.
   */
  public readonly oidcClient: MonoCloudOidcClient;

  private readonly options: MonoCloudWebJSClientOptions;

  private postCallbackFn: PostCallback = state => {
    if (!state.returnUrl) {
      const url = new URL(window.location.href);
      url.search = '';
      url.hash = '';
      history.replaceState({}, document.title, url.href);
    } else {
      // eslint-disable-next-line no-console
      console.warn(
        'Warning: The default behavior for return URL is to perform a full page reload, which resets all data when using MemoryStorage. To integrate with a client-side router, pass a custom postCallback() function during client initialization.'
      );
      window.location.href = state.returnUrl;
    }
  };

  private readonly onSessionCreating?: OnSessionCreating;

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
    return (
      this.options.defaultAuthParams?.responseType ??
      AUTH_CONSTANTS.DEFAULT_RESPONSE_TYPE
    );
  }

  private get federatedSignOut(): boolean {
    return (
      this.options.federatedSignOut ?? AUTH_CONSTANTS.DEFAULT_FEDERATED_SIGNOUT
    );
  }

  private get redirectUri(): string {
    return `${this.options.appUrl}${ensureLeadingSlash(this.options.callbackPath ?? '/')}`;
  }

  private get signOutRedirectUri(): string {
    return `${this.options.appUrl}${ensureLeadingSlash(this.options.signOutCallbackPath ?? '/')}`;
  }

  private get callbackStateKey(): string {
    return `${AUTH_CONSTANTS.CALLBACK_KEY}.${this.options.clientId}`;
  }

  private get lockKey(): string {
    return `${AUTH_CONSTANTS.LOCK_KEY}.${this.options.clientId}${this.options.sessionKey ? `.${this.options.sessionKey}` : ''}`;
  }

  private dedupeKey(...parts: (string | boolean | undefined)[]): string {
    return `${this.lockKey}.${parts.filter(isPresent).join('.')}`;
  }

  private set redirectCallbackState(state: CallbackState | undefined) {
    if (!state) {
      window.sessionStorage.removeItem(this.callbackStateKey);
      return;
    }

    window.sessionStorage.setItem(this.callbackStateKey, JSON.stringify(state));
  }

  private get redirectCallbackState(): CallbackState | undefined {
    const stored = window.sessionStorage.getItem(this.callbackStateKey);

    if (!stored) {
      return undefined;
    }

    try {
      return JSON.parse(stored);
    } catch (error) {
      window.sessionStorage.removeItem(this.callbackStateKey);
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
    try {
      return window.top === window.self;
    } catch {
      /* v8 ignore next -- @preserve cross-origin frame access */
      return false;
    }
  }

  private get isSameParent(): boolean {
    try {
      return window.parent === window.self;
    } catch {
      /* v8 ignore next -- @preserve cross-origin frame access */
      return false;
    }
  }

  private get hasOpener(): boolean {
    try {
      return window.opener !== null && window.opener !== undefined;
    } catch {
      /* v8 ignore next -- @preserve cross-origin frame access */
      return false;
    }
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
   * Initializes a new instance of {@link MonoCloudWebJSClient}.
   *
   * @example Default Integration
   * ```typescript:src/auth.ts tab="Default Integration" tab-group="constructor"
   * import { MonoCloudWebJSClient } from '@monocloud/auth-web-js';
   *
   * export const client = new MonoCloudWebJSClient({
   *   tenantDomain: 'https://your-tenant.us.monocloud.com',
   *   clientId: 'your-client-id',
   *   appUrl: 'http://localhost:3000',
   * });
   * ```
   *
   * @example Custom Storage & Router
   * ```typescript:src/auth.ts tab="Custom Storage & Router" tab-group="constructor"
   * import { MonoCloudWebJSClient, MemoryStorage } from '@monocloud/auth-web-js';
   * import { router } from './router';
   *
   * export const client = new MonoCloudWebJSClient({
   *   tenantDomain: 'https://your-tenant.us.monocloud.com',
   *   clientId: 'your-client-id',
   *   appUrl: 'http://localhost:3000',
   *   storage: new MemoryStorage(),
   *   postCallback: state => {
   *     // Use the router to navigate instead of a full page reload.
   *     router.push(state.returnUrl ?? '/dashboard');
   *   },
   * });
   * ```
   *
   * @param options Configuration options for the client.
   */
  constructor(options: MonoCloudWebJSClientOptions) {
    this.options = {
      ...options,
      appUrl: removeTrailingSlash(options.appUrl),
    };

    this.storage = options.storage ?? new LocalStorage();
    if (options.postCallback) {
      this.postCallbackFn = options.postCallback;
    }

    this.onSessionCreating = options.onSessionCreating;

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
   * Processes the authentication callback from the authorization server.
   *
   * Call this once on application startup (typically in your entry point or
   * router). It inspects the current URL together with the persisted callback
   * state and automatically completes a pending sign-in or sign-out flow -
   * there is no need to dispatch on the route yourself.
   *
   *
   * @example Application Entry
   * ```typescript:src/main.ts
   * import { client } from './auth';
   *
   * async function init() {
   *   // Complete any pending redirect callback before rendering.
   *   await client.processCallback();
   *
   *   // Continue mounting the app.
   *   renderApp();
   * }
   *
   * init();
   * ```
   *
   * @returns A promise that resolves when callback processing is complete.
   */
  async processCallback(): Promise<void> {
    const currentUrl = new URL(window.location.href);
    const currentPath = `${currentUrl.origin}${currentUrl.pathname}`;

    const isSignInPath = currentPath === this.redirectUri;
    const isSignOutPath = currentPath === this.signOutRedirectUri;

    if (!this.mainWindow) {
      if (isSignInPath || isSignOutPath) {
        this.postCallbackToParent();
      }
      return;
    }

    const callbackState = this.redirectCallbackState;
    this.redirectCallbackState = undefined;

    if (!callbackState) {
      return;
    }

    if (isSignInPath && !callbackState.signOut) {
      await this.internalProcessSignInCallback(
        window.location.href,
        callbackState
      );
    } else if (isSignOutPath && callbackState.signOut) {
      await this.internalProcessSignOutCallback(
        window.location.href,
        callbackState
      );
    }
  }

  /**
   * Initiates the sign-in flow.
   *
   * @example Redirect Flow
   * ```typescript:src/app.ts tab="Redirect Flow" tab-group="signIn"
   * document.getElementById('login-btn')!.addEventListener('click', async () => {
   *   // Standard top-level redirect to the authorization server.
   *   await client.signIn();
   * });
   * ```
   *
   * @example Popup Flow
   * ```typescript:src/app.ts tab="Popup Flow" tab-group="signIn"
   * document.getElementById('login-popup-btn')!.addEventListener('click', async () => {
   *   // Opens a centered popup for authentication.
   *   await client.signIn({ mode: 'popup' });
   *   console.log('User finished popup flow!');
   * });
   * ```
   *
   * @example Sign Up
   * ```typescript:src/app.ts tab="Sign Up" tab-group="signIn"
   * document.getElementById('register-btn')!.addEventListener('click', async () => {
   *   // Forces the identity provider to show the registration/sign-up screen.
   *   await client.signIn({ signUp: true });
   * });
   * ```
   *
   * @param signInOptions Optional configuration for the sign-in request.
   */
  async signIn(signInOptions?: SignInOptions): Promise<void> {
    const mode = signInOptions?.mode ?? 'redirect';

    const paramOverrides: Partial<AuthorizationParams> = {
      uiLocales: signInOptions?.uiLocales,
      authenticatorHint: signInOptions?.authenticatorHint,
      loginHint: signInOptions?.loginHint,
      maxAge: signInOptions?.maxAge,
      prompt: signInOptions?.signUp ? 'create' : signInOptions?.prompt,
      display: signInOptions?.display,
      acrValues: signInOptions?.acrValues,
      scopes: signInOptions?.scopes,
      resource: signInOptions?.resource,
    };

    const callbackStateOverrides: Partial<CallbackState> = {
      maxAge: signInOptions?.maxAge,
      returnUrl: signInOptions?.returnUrl,
      appState: signInOptions?.appState,
    };

    if (mode === 'redirect') {
      if (this.isIframe) {
        throw new MonoCloudJsError(
          "Cannot start a redirect sign-in from inside an iframe: the MonoCloud sign-in page cannot be displayed in a framed context. Use signIn({ mode: 'popup' }) instead, or perform the redirect on the top-level window."
        );
      }

      const { url, callbackState } = await this.buildAuthRequest(
        mode,
        paramOverrides,
        callbackStateOverrides
      );
      this.redirectCallbackState = callbackState;
      window.location.assign(url);
      return;
    }

    await this.performInteractiveAuth(
      mode,
      paramOverrides,
      callbackStateOverrides
    );
  }

  /**
   * Initiates the sign-out flow.
   *
   * Clears the local session and, when `federatedSignOut` is enabled, also signs the user out of MonoCloud (Single Sign-Out).
   *
   * @example Standard Sign Out
   * ```typescript:src/app.ts tab="Redirect Flow" tab-group="signOut"
   * document.getElementById('logout-btn')!.addEventListener('click', async () => {
   *   await client.signOut();
   * });
   * ```
   *
   * @example Popup Sign Out
   * ```typescript:src/app.ts tab="Popup Flow" tab-group="signOut"
   * document.getElementById('logout-popup-btn')!.addEventListener('click', async () => {
   *   // Opens a popup to perform federated sign-out while keeping the user on the current page.
   *   await client.signOut({ mode: 'popup' });
   * });
   * ```
   *
   * @param signOutOptions Optional configuration for the sign-out request.
   * @returns A promise that resolves when the sign-out flow has been initiated (redirect mode) or completed (popup mode).
   */
  async signOut(signOutOptions?: SignOutOptions): Promise<void> {
    const mode = signOutOptions?.mode ?? 'redirect';
    const federatedSignOut =
      signOutOptions?.federatedSignOut ?? this.federatedSignOut;

    if (mode === 'redirect' && federatedSignOut && this.isIframe) {
      throw new MonoCloudJsError(
        "Cannot start a redirect sign-out from inside an iframe: the MonoCloud end-session page cannot be displayed in a framed context. Use signOut({ mode: 'popup' }) instead, or perform the redirect on the top-level window."
      );
    }

    const ref =
      federatedSignOut && mode === 'popup' ? this.createRef(mode) : undefined;

    try {
      const session = await this.getSession();

      this.redirectCallbackState = undefined;

      await this.setSession();

      if (!federatedSignOut) {
        return;
      }

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

      const state = postLogoutRedirectUri ? generateState() : undefined;

      const url = await this.oidcClient.endSessionUrl({
        idToken: session?.idToken,
        postLogoutRedirectUri,
        state,
      });

      const callbackState: CallbackState = {
        mode,
        state,
        signOut: true,
        returnUrl: signOutOptions?.returnUrl,
      };

      if (mode === 'redirect') {
        this.redirectCallbackState = callbackState;
        window.location.assign(url);
        return;
      }

      /* v8 ignore if -- @preserve */
      if (!ref?.getRef()) {
        throw new MonoCloudJsError('Popup or Iframe creation failed');
      }

      const callbackUrl = await this.authWindow(url, ref);

      await this.internalProcessSignOutCallback(callbackUrl, callbackState);
    } finally {
      ref?.close();
    }
  }

  /**
   * Refreshes the current user's session using the OAuth 2.0 Refresh Token Grant.
   *
   * Requires a session that includes a refresh token (obtained by including the `offline_access` scope at sign-in).
   *
   * To start a fresh, non-interactive authorization (for example, on app bootstrap when there is no local session yet) use {@link MonoCloudWebJSClient.signInSilent} instead.
   *
   * @example Usage
   * ```typescript:src/app.ts
   * await client.refreshSession();
   * ```
   *
   * @example Resource-Scoped Refresh
   * ```typescript:src/app.ts
   * await client.refreshSession({
   *   refreshGrantOptions: {
   *     resource: 'https://api.example.com',
   *     scopes: 'read:data',
   *   },
   * });
   * ```
   *
   * @param refreshOptions Optional configuration for the refresh flow.
   * @returns A promise that resolves when the session has been refreshed.
   * @throws {@link MonoCloudValidationError} If the session is invalid or missing a refresh token.
   */
  async refreshSession(refreshOptions?: RefreshOptions): Promise<void> {
    const dedupeKey = this.dedupeKey(
      'refresh',
      refreshOptions?.refreshGrantOptions?.resource,
      refreshOptions?.refreshGrantOptions?.scopes
    );

    return await withDedupedLock(dedupeKey, this.lockKey, async () => {
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

  /**
   * Attempts to silently sign the user in using a hidden iframe and `prompt=none`.
   *
   * Useful for restoring a session at app bootstrap when the user is signed in at MonoCloud but no local session exists yet (for example, after opening a new tab or a hard refresh that cleared in-memory storage).
   *
   * The method runs a full authorization round-trip through a hidden iframe. If MonoCloud has a valid session it resolves to the new session. Otherwise it rejects with a {@link MonoCloudOPError} - typically with `error: 'login_required'`, `'interaction_required'`, `'consent_required'`, or `'account_selection_required'`, depending on why the authorization server cannot satisfy the request without user interaction.
   *
   * @example App Bootstrap
   * ```typescript:src/app.ts
   * import { MonoCloudOPError } from '@monocloud/auth-web-js';
   *
   * try {
   *   const session = await client.signInSilent();
   *   console.log('Restored session for:', session.user);
   * } catch (error) {
   *   if (error instanceof MonoCloudOPError && error.error === 'login_required') {
   *     console.log('Not signed in');
   *   } else {
   *     throw error;
   *   }
   * }
   * ```
   *
   * @example Resource-Scoped Silent Sign In
   * ```typescript:src/app.ts
   * await client.signInSilent({
   *   resource: 'https://api.example.com',
   *   scopes: 'read:data',
   * });
   * ```
   *
   * @param signInSilentOptions Optional configuration for the silent sign-in request.
   * @returns The newly established session.
   * @throws {@link MonoCloudOPError} If the authorization server cannot satisfy the request - for example, because the user has no IdP session (`login_required`) or interaction is otherwise required.
   * @throws {@link MonoCloudJsError} If the iframe cannot be created (for example, in a cross-origin-isolated context) or the authentication window times out.
   */
  async signInSilent(
    signInSilentOptions?: SignInSilentOptions
  ): Promise<MonoCloudSession> {
    const dedupeKey = this.dedupeKey(
      'signInSilent',
      signInSilentOptions?.resource,
      signInSilentOptions?.scopes
    );

    return await withDedupedLock(dedupeKey, this.lockKey, async () => {
      await this.performInteractiveAuth(
        'silent',
        {
          prompt: 'none',
          scopes: signInSilentOptions?.scopes,
          resource: signInSilentOptions?.resource,
        },
        {
          appState: signInSilentOptions?.appState,
        }
      );

      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      return (await this.getSession())!;
    });
  }

  /**
   * Refetches user information from the UserInfo endpoint and updates the local session.
   *
   * The default access token (matching the client's configured default resource and authorized scopes) is used to call the UserInfo endpoint.
   *
   * @example Usage
   * ```typescript:src/app.ts
   * await client.refetchUserInfo();
   * const session = await client.getSession();
   * console.log('Updated user data:', session?.user);
   * ```
   *
   * @throws {@link MonoCloudValidationError} If the session is invalid or the default access token is missing.
   */
  async refetchUserInfo(): Promise<void> {
    return await withDedupedLock(
      this.dedupeKey('refetchUserInfo'),
      this.lockKey,
      async () => {
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
    );
  }

  /**
   * Retrieves the active tokens for the current session.
   *
   * If the access token is expired (or about to expire), this method automatically attempts to refresh it using the Refresh Token Grant before returning.
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
   *   resource: 'https://api.example.com',
   *   scopes: 'read:data',
   * });
   * ```
   *
   * @param options Options that control token retrieval (force refresh, scopes, resource).
   * @returns The active tokens for the requested resource and scopes.
   * @throws {@link MonoCloudValidationError} If no session exists or the access token cannot be located.
   */
  async getTokens(options?: GetTokensOptions): Promise<MonoCloudTokens> {
    const dedupeKey = this.dedupeKey(
      'getTokens',
      options?.resource,
      options?.scopes,
      !!options?.forceRefresh,
      !!options?.refetchUserInfo
    );

    return await withDedupedLock(dedupeKey, this.lockKey, async () => {
      const session = await this.getSession();

      if (!session) {
        throw new MonoCloudValidationError('Session does not exist');
      }

      let scopes = options?.scopes;

      const resource =
        options?.resource ?? this.options.defaultAuthParams?.resource;

      if (isPresent(options?.resource)) {
        if (!isPresent(scopes)) {
          const noScopeResource = this.options.resources?.find(
            x =>
              setsEqual(
                parseSpaceSeparatedSet(x.resource),
                parseSpaceSeparatedSet(resource)
              ) && !x.scopes
          );

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
          validateIdToken: this.validateIdToken,
          idTokenClockSkew: this.clockSkew,
          idTokenClockTolerance: this.clockTolerance,
          refreshGrantOptions: {
            resource,
            scopes,
          },
          filteredIdTokenClaims: this.filteredIdTokenClaims,
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

      /* v8 ignore next 3 -- @preserve */
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
   * Retrieves the current session object from the configured storage.
   *
   * @example Usage
   * ```typescript:src/app.ts
   * const session = await client.getSession();
   * if (session) {
   *   console.log('User is logged in:', session.user);
   * }
   * ```
   *
   * @returns The active session, or `undefined` if not authenticated.
   */
  async getSession(): Promise<MonoCloudSession | undefined> {
    const value = await this.storage.getItem(this.sessionKey);
    if (!value) {
      return undefined;
    }

    return JSON.parse(value);
  }

  private async setSession(session?: MonoCloudSession): Promise<void> {
    if (!session) {
      await this.storage.removeItem(this.sessionKey);
      return;
    }

    await this.storage.setItem(this.sessionKey, JSON.stringify(session));
  }

  private async buildAuthRequest(
    mode: CallbackState['mode'],
    paramOverrides: Partial<AuthorizationParams>,
    callbackStateOverrides: Partial<CallbackState>
  ): Promise<{ url: string; callbackState: CallbackState }> {
    const { codeChallenge, codeVerifier } = await generatePKCE();
    const state = generateState();
    const nonce = generateNonce();

    const { mergedScopes, mergedResources } = this.mergeAuthParams(
      paramOverrides.scopes,
      paramOverrides.resource
    );

    const params: AuthorizationParams = {
      ...paramOverrides,
      responseType: this.responseType,
      scopes: mergedScopes,
      codeChallenge,
      codeChallengeMethod: 'S256',
      redirectUri: this.redirectUri,
      state,
      nonce,
      resource: mergedResources,
    };

    const url = await this.oidcClient.authorizationUrl(params);

    let resource = this.options.defaultAuthParams?.resource;
    if (
      params.responseType === 'token' ||
      params.responseType === 'id_token token'
    ) {
      resource = mergedResources;
    }

    const callbackState: CallbackState = {
      ...callbackStateOverrides,
      state,
      codeVerifier,
      nonce,
      mode,
      scopes: params.scopes,
      responseType: this.responseType,
      resource,
    };

    return { url, callbackState };
  }

  private mergeAuthParams(
    overrideScopes?: string,
    overrideResource?: string
  ): { mergedScopes: string; mergedResources: string | undefined } {
    const indicatorResource = this.options.resources
      ?.map(x => x.resource)
      .filter((x): x is string => !!x)
      .join(' ');
    const indicatorScopes = this.options.resources
      ?.map(x => x.scopes)
      .filter((x): x is string => !!x)
      .join(' ');

    const mergedScopes =
      mergeArrays(
        parseSpaceSeparated(overrideScopes),
        parseSpaceSeparated(this.options.defaultAuthParams?.scopes),
        parseSpaceSeparated(indicatorScopes)
      )?.join(' ') ?? AUTH_CONSTANTS.DEFAULT_SCOPES;

    const mergedResources = mergeArrays(
      parseSpaceSeparated(overrideResource),
      parseSpaceSeparated(this.options.defaultAuthParams?.resource),
      parseSpaceSeparated(indicatorResource)
    )?.join(' ');

    return { mergedScopes, mergedResources };
  }

  private async performInteractiveAuth(
    mode: 'popup' | 'silent',
    paramOverrides: Partial<AuthorizationParams>,
    callbackStateOverrides: Partial<CallbackState>
  ): Promise<void> {
    const ref = this.createRef(mode);
    try {
      const { url, callbackState } = await this.buildAuthRequest(
        mode,
        paramOverrides,
        callbackStateOverrides
      );

      const callbackUrl = await this.authWindow(url, ref);
      await this.internalProcessSignInCallback(callbackUrl, callbackState);
    } finally {
      ref.close();
    }
  }

  private async internalProcessSignInCallback(
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

    if (!isPresent(callbackState.responseType)) {
      throw new MonoCloudValidationError(
        'Response type missing from callback state'
      );
    }

    const callbackParams = parseCallbackParams(
      callbackState.responseType === 'code' ? url.search : url.hash
    );

    if (callbackState.state && callbackParams.state !== callbackState.state) {
      throw new MonoCloudValidationError('Sign in callback states mismatch');
    }

    if (callbackParams.error) {
      throw new MonoCloudOPError(
        callbackParams.error,
        callbackParams.errorDescription
      );
    }

    const { accessToken, idToken, code } = callbackParams;

    switch (callbackState.responseType) {
      case 'code':
        if (!isPresent(code)) {
          throw new MonoCloudValidationError("Response is missing 'code'");
        }
        break;

      case 'token':
        if (!isPresent(accessToken)) {
          throw new MonoCloudValidationError(
            "Response is missing 'access_token'"
          );
        }
        break;

      case 'id_token':
        if (!isPresent(idToken)) {
          throw new MonoCloudValidationError("Response is missing 'id_token'");
        }
        break;

      case 'id_token token':
        if (!isPresent(idToken) || !isPresent(accessToken)) {
          throw new MonoCloudValidationError(
            "Response is missing 'id_token' or 'access_token'"
          );
        }
        break;

      case 'code id_token':
        if (!isPresent(code) || !isPresent(idToken)) {
          throw new MonoCloudValidationError(
            "Response is missing 'code' or 'id_token'"
          );
        }
        break;

      case 'code token':
        if (!isPresent(code) || !isPresent(accessToken)) {
          throw new MonoCloudValidationError(
            "Response is missing 'code' or 'access_token'"
          );
        }
        break;

      case 'code id_token token':
        if (
          !isPresent(code) ||
          !isPresent(idToken) ||
          !isPresent(accessToken)
        ) {
          throw new MonoCloudValidationError(
            "Response is missing 'code', 'id_token', or 'access_token'"
          );
        }
        break;

      default:
        throw new MonoCloudValidationError(
          `Unsupported response_type: ${callbackState.responseType}`
        );
    }

    const isImplicit =
      callbackState.responseType === 'token' ||
      callbackState.responseType === 'id_token token' ||
      callbackState.responseType === 'id_token';

    if (isImplicit) {
      let idTokenClaims = {} as IdTokenClaims;
      if (
        callbackState.responseType === 'id_token' ||
        callbackState.responseType === 'id_token token'
      ) {
        if (this.validateIdToken) {
          const jwks = await this.oidcClient.getJwks();
          idTokenClaims = await this.oidcClient.validateIdToken(
            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            idToken!,
            jwks.keys,
            this.clockSkew,
            this.clockTolerance,
            callbackState.maxAge,
            callbackState.nonce
          );
        } else {
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          idTokenClaims = MonoCloudOidcClient.decodeJwt(idToken!);
        }

        this.filteredIdTokenClaims.forEach(claim => {
          // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
          delete (idTokenClaims as Record<string, unknown>)[claim];
        });
      }

      let userinfo = {} as unknown as UserinfoResponse;

      const accessTokens: AccessToken[] = [];

      if (
        callbackState.responseType === 'token' ||
        callbackState.responseType === 'id_token token'
      ) {
        if (!isPresent(callbackParams.expiresIn)) {
          throw new MonoCloudValidationError(
            "The 'expires_in' parameter is missing from the callback"
          );
        }

        const scopes = callbackParams.scope ?? callbackState.scopes;

        if (this.fetchUserinfo) {
          if (!scopes.includes('openid')) {
            throw new MonoCloudValidationError(
              'Fetching userinfo requires the openid scope'
            );
          }
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          userinfo = await this.oidcClient.userinfo(accessToken!);
        }

        accessTokens.push({
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          accessToken: accessToken!,
          scopes,
          requestedScopes: callbackState.scopes,
          resource: callbackState.resource,
          accessTokenExpiration: now() + callbackParams.expiresIn,
        });
      }

      const session: MonoCloudSession = {
        user: {
          ...idTokenClaims,
          ...userinfo,
        },
        idToken: callbackParams.idToken,
        accessTokens,
        refreshToken: callbackParams.refreshToken,
        authorizedScopes: callbackState.scopes,
      };

      await this.onSessionCreating?.(
        session,
        idTokenClaims,
        userinfo,
        callbackState.appState
      );

      await this.setSession(session);

      await this.postCallbackFn({
        type: 'signIn',
        returnUrl: callbackState.returnUrl,
        mode: callbackState.mode,
      });
      return;
    }

    // Authorization Code or Hybrid flow.
    const session = await this.oidcClient.authenticate(
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      code!,
      this.redirectUri,
      callbackState.scopes,
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
  }

  private async internalProcessSignOutCallback(
    callbackUrl: string,
    callbackState: CallbackState
  ): Promise<void> {
    await this.setSession();
    const url = new URL(callbackUrl);

    if (
      ensureLeadingSlash(this.options.signOutCallbackPath ?? '/') !==
      url.pathname
    ) {
      throw new MonoCloudValidationError('Incorrect callback url');
    }

    if (!callbackState.signOut) {
      throw new MonoCloudValidationError('Incorrect callback state');
    }

    const callbackParams = parseCallbackParams(url.search);

    if (callbackState.state && callbackParams.state !== callbackState.state) {
      throw new MonoCloudValidationError('Sign out states mismatch');
    }

    await this.postCallbackFn({
      type: 'signOut',
      returnUrl: callbackState.returnUrl,
      mode: callbackState.mode as InteractionMode,
    });
  }

  private postCallbackToParent(): void {
    const parentWindow = (window.opener ?? window.parent) as Window;

    parentWindow.postMessage(
      {
        source: 'monocloud-auth-web-js',
        url: window.location.href,
      },
      this.appOrigin
    );
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

      const listener = (e: MessageEvent<unknown>): void => {
        if (e.origin !== this.appOrigin) {
          return;
        }

        if (!e.data || typeof e.data !== 'object') {
          return;
        }

        const data = e.data as Partial<PostMessageResult>;
        if (!isPresent(data.url) || typeof data.url !== 'string') {
          return;
        }

        if (e.source !== ref.getWindow()) {
          return;
        }

        if (data.source !== 'monocloud-auth-web-js') {
          return;
        }

        abort();
        resolve(data.url);
      };

      timeoutTimer = setTimeout(() => {
        abort();
        reject(new MonoCloudJsError('Authentication window timed out'));
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

  private createRef(mode: 'popup' | 'silent'): Ref {
    return mode === 'popup' ? this.createPopup() : this.createIframe();
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
      throw new MonoCloudJsError(
        'Cannot create iframe in a cross-origin-isolated context'
      );
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
