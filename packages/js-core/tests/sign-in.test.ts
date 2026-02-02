// eslint-disable-next-line import/no-extraneous-dependencies
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  fetchBuilder,
  generateIdToken,
  MockWindow,
} from '@monocloud/auth-test-utils';
import { testInstance, VanillaJsMockStorage } from './utils';
import {
  CallbackState,
  MonoCloudHttpError,
  MonoCloudJsError,
  MonoCloudOPError,
  MonoCloudTokenError,
  MonoCloudValidationError,
} from '../src';
import { now } from '@monocloud/auth-core/internal';

describe('signIn() Tests', () => {
  let mockWindow: MockWindow;
  let storage: VanillaJsMockStorage;

  const urlRegex =
    /^https:\/\/example\.com\/connect\/authorize\?client_id=clientId&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=[a-zA-Z0-9+_% -]+&response_type=[a-zA-Z0-9_]+&nonce=[a-zA-Z0-9_-]+&code_challenge=[a-zA-Z0-9_-]+&code_challenge_method=S256&state=[a-zA-Z0-9_-]+$/;

  beforeEach(() => {
    storage = new VanillaJsMockStorage();
    mockWindow = new MockWindow();
  });

  afterEach(() => {
    mockWindow.restore();
    window.localStorage.clear();
  });

  it('should redirect to the sign in page', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow
      .expectOrigin('https://example.com/connect/authorize')
      .expectQueryKey('state')
      .expectQueryKey('code_challenge')
      .expectQueryKey('nonce')
      .expectQuery('code_challenge_method', 'S256')
      .expectQuery('client_id', 'clientId')
      .expectQuery('response_type', 'code')
      .expectQuery('scope', 'openid')
      .expectQuery('redirect_uri', 'http://localhost:3000/callback')
      .assert();

    const instance = testInstance({ storage });

    await instance.signIn();

    expect(window.location.assign).toHaveBeenCalledOnce();
    fetchSpy.assert();
  });

  it('should throw error if the code is not running in the main window', async () => {
    vi.spyOn(window, 'opener', 'get').mockReturnValue(null);
    vi.spyOn(window, 'parent', 'get').mockReturnValue({} as unknown as Window);
    vi.spyOn(window, 'top', 'get').mockReturnValue({} as unknown as Window);

    const instance = testInstance({ storage });

    const signInPromise = instance.signIn();

    await expect(signInPromise).rejects.toThrow(MonoCloudJsError);
    await expect(signInPromise).rejects.toThrow(
      'Initiating an authentication flow in a popup or iframe is not supported'
    );
  });

  it('should redirect to the appUrl if callback path is undefined', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow
      .expectOrigin('https://example.com/connect/authorize')
      .expectQuery('redirect_uri', 'http://localhost:3000/')
      .assert();

    const instance = testInstance({
      storage,
      callbackPath: undefined,
    });

    await instance.signIn();

    expect(window.location.assign).toHaveBeenCalledOnce();
    fetchSpy.assert();
  });

  it('should redirect to sign in page with the preferred authenticator', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.expectQuery('authenticator_hint', 'apple').assert();

    const instance = testInstance({ storage });

    await instance.signIn({ authenticatorHint: 'apple' });

    expect(window.location.assign).toHaveBeenCalledOnce();

    fetchSpy.assert();
  });

  it('should redirect to sign in page with the login hint', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.expectQuery('login_hint', 'username').assert();

    const instance = testInstance({
      storage,
    });

    await instance.signIn({ loginHint: 'username' });

    expect(window.location.assign).toHaveBeenCalledOnce();
    fetchSpy.assert();
  });

  it('should redirect to sign up page', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.expectQuery('prompt', 'create').assert();

    const instance = testInstance({ storage });

    await instance.signIn({ signUp: true });

    expect(window.location.assign).toHaveBeenCalledOnce();
    fetchSpy.assert();
  });

  it('should set max age and ui locales', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow
      .expectQuery('ui_locales', 'en-US')
      .expectQuery('max_age', '5')
      .assert();

    const instance = testInstance({ storage });

    await instance.signIn({ uiLocales: 'en-US', maxAge: 5 });

    expect(window.location.assign).toHaveBeenCalledOnce();
    fetchSpy.assert();
  });

  it('Redirect Mode - should redirect to sign in page', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const instance = testInstance({ storage });

    await instance.signIn();

    storage
      .expectCallbackState()
      .expectCallbackStateMode('redirect')
      .expectCallbackStateCodeVerifier()
      .expectCallbackStateMaxAge(undefined)
      .expectCallbackStateNonce()
      .expectCallbackStateSignOut(undefined)
      .expectCallbackStateState();

    expect(window.location.assign).toHaveBeenCalledWith(
      expect.stringContaining('https://example.com/connect/authorize')
    );
    fetchSpy.assert();
  });

  it('Redirect Mode - should process callback using the default callback state key', async () => {
    const idToken = await generateIdToken({ nonce: 'nonce' });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureTokenEndpoint({
        idToken,
        body: 'grant_type=authorization_code&code=code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_verifier=codeVerifier',
      })
      .configureUserinfo()
      .createSpy();

    mockWindow
      .setSearch('?state=state&code=code')
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      codeVerifier: 'codeVerifier',
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid offline_access',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage });

    await instance.processCallback();

    storage.expectCallbackStateRemoved().expectSession();
    expect(await instance.getSession()).toBeDefined();

    fetchSpy.assert();
  });

  it('Redirect Mode - should not process callback if there is no callback state found', async () => {
    mockWindow
      .setSearch('?state=state&code=code')
      .setPathname('/callback')
      .assert();

    const instance = testInstance({ storage });

    await instance.processCallback();

    storage.expectCallbackStateRemoved().expectNoSession();
    expect(await instance.getSession()).toBeUndefined();
  });

  it('Redirect Mode - should process a redirect callback (Authorization Code)', async () => {
    const idToken = await generateIdToken({ nonce: 'nonce' });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureTokenEndpoint({
        idToken,
        body: 'grant_type=authorization_code&code=code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_verifier=codeVerifier',
      })
      .configureUserinfo()
      .createSpy();

    mockWindow
      .setSearch('?state=state&code=code')
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      codeVerifier: 'codeVerifier',
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid offline_access',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage });

    await instance.processCallback();

    storage.expectCallbackStateRemoved().expectSession();

    const session = await instance.getSession();

    expect(session).toBeDefined();

    expect(session?.user).toEqual(
      expect.objectContaining({
        sub: 'sub',
        username: 'username',
      })
    );

    expect(session?.refreshToken).toBe('rt');
    expect(session?.authorizedScopes).toBe('openid offline_access');
    expect(session?.idToken).toBe(idToken);

    expect(session?.accessTokens).toHaveLength(1);
    expect(session?.accessTokens?.[0].accessToken).toBe('at');
    expect(session?.accessTokens?.[0].scopes).toBe('openid offline_access');

    const expiration = session?.accessTokens?.[0].accessTokenExpiration;
    expect(expiration).toBeDefined();
    expect(expiration).toBeLessThanOrEqual(now() + 1000);
    expect(expiration).toBeGreaterThan(now() + 900);

    fetchSpy.assert();
  });

  it('should execute postCallback function', async () => {
    const idToken = await generateIdToken({ nonce: 'nonce' });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureTokenEndpoint({
        idToken,
        body: 'grant_type=authorization_code&code=code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_verifier=codeVerifier',
      })
      .configureUserinfo()
      .createSpy();

    mockWindow
      .setSearch('?state=state&code=code')
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      codeVerifier: 'codeVerifier',
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid offline_access',
    };

    storage.setCallbackState(state);

    const fn = vi.fn();

    const instance = testInstance({ storage, postCallback: fn });

    await instance.processCallback();

    const session = await instance.getSession();

    expect(session?.user).toBeDefined();
    expect(fn).toHaveBeenCalledTimes(1);
    fetchSpy.assert();
  });

  it('should set href to returnUrl if set', async () => {
    const idToken = await generateIdToken({ nonce: 'nonce' });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureTokenEndpoint({
        idToken,
        body: 'grant_type=authorization_code&code=code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_verifier=codeVerifier',
      })
      .configureUserinfo()
      .createSpy();

    mockWindow
      .setSearch('?state=state&code=code')
      .setPathname('/callback')
      .expectHrefCalled('/test')
      .assert();

    const state: CallbackState = {
      codeVerifier: 'codeVerifier',
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid offline_access',
      returnUrl: '/test',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage });

    await instance.processCallback();

    const session = await instance.getSession();

    expect(session?.user).toBeDefined();
    fetchSpy.assert();
  });

  it('should use default path for processing callback if the callback path is undefined', async () => {
    const idToken = await generateIdToken({ nonce: 'nonce' });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureTokenEndpoint({
        idToken,
        body: 'grant_type=authorization_code&code=code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2F&code_verifier=codeVerifier',
      })
      .configureUserinfo()
      .createSpy();

    mockWindow.setSearch('?state=state&code=code').setPathname('/').assert();

    const state: CallbackState = {
      codeVerifier: 'codeVerifier',
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid offline_access',
    };

    storage.setCallbackState(state);

    const instance = testInstance({
      storage,
      callbackPath: undefined,
    });

    await instance.processCallback();

    storage.expectCallbackStateRemoved();

    const session = await instance.getSession();
    expect(session).toBeDefined();
    expect(session?.accessTokens?.[0].accessToken).toBe('at');

    fetchSpy.assert();
  });

  it("Redirect Mode - should process a redirect callback (Hybrid - 'code token id_token' response type)", async () => {
    const idToken = await generateIdToken({ nonce: 'nonce' });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureTokenEndpoint({
        idToken,
        body: 'grant_type=authorization_code&code=code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_verifier=codeVerifier',
      })
      .configureUserinfo()
      .createSpy();

    mockWindow
      .setSearch(
        '?state=state&code=code&access_token=at&expires_in=600&id_token=idtoken&refresh_token=rt'
      )
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      state: 'state',
      mode: 'redirect',
      codeVerifier: 'codeVerifier',
      nonce: 'nonce',
      scopes: 'openid offline_access',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage });

    await instance.processCallback();
    storage.expectCallbackStateRemoved();
    const session = await instance.getSession();

    expect(session).toBeDefined();

    expect(session?.user.sub).toBe('sub');

    expect(session?.refreshToken).toBe('rt');
    expect(session?.authorizedScopes).toBe('openid offline_access');
    expect(session?.idToken).toBe(idToken);

    expect(session?.accessTokens).toHaveLength(1);
    expect(session?.accessTokens?.[0].accessToken).toBe('at');

    expect(
      session?.accessTokens?.[0].accessTokenExpiration
    ).toBeLessThanOrEqual(now() + 1000);

    fetchSpy.assert();
  });

  it("Redirect Mode - should process a redirect callback (Implicit - 'token' response type)", async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureUserinfo()
      .createSpy();

    mockWindow
      .setSearch('?state=state&access_token=at&expires_in=600&scope=openid')
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      state: 'state',
      mode: 'redirect',
      scopes: 'openid offline_access',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage });

    await instance.processCallback();

    storage.expectCallbackStateRemoved();

    const session = await instance.getSession();

    expect(session).toBeDefined();

    expect(session?.user).toBeDefined();

    expect(session?.refreshToken).toBeUndefined();
    expect(session?.idToken).toBeUndefined();

    expect(session?.accessTokens).toHaveLength(1);
    expect(session?.accessTokens?.[0].accessToken).toBe('at');
    expect(
      session?.accessTokens?.[0].accessTokenExpiration
    ).toBeLessThanOrEqual(now() + 600);

    fetchSpy.assert();
  });

  it("Redirect Mode - should process a redirect callback (Implicit - 'id_token' response type)", async () => {
    const idToken = await generateIdToken({
      nonce: 'nonce',
      claims: { sub: 'some' },
    });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .createSpy();

    mockWindow
      .setSearch(`?state=state&id_token=${idToken}`)
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage });

    await instance.processCallback();

    storage.expectCallbackStateRemoved();

    const session = await instance.getSession();

    expect(session).toBeDefined();
    expect(session?.user).toBeDefined();
    expect(session?.user.sub).toBe('some');
    expect(session?.idToken).toBe(idToken);

    expect(session?.refreshToken).toBeUndefined();
    expect(session?.authorizedScopes).toBeUndefined();

    expect(session?.accessTokens?.[0]?.accessToken).toBeUndefined();
    expect(session?.accessTokens?.[0]?.accessTokenExpiration).toBeUndefined();

    fetchSpy.assert();
  });

  it("Redirect Mode - should process a redirect callback (Implicit - 'id_token token' response type)", async () => {
    const idToken = await generateIdToken({
      nonce: 'nonce',
      claims: { sub: 'some' },
    });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureUserinfo({ claims: { sub: 'some' } })
      .createSpy();

    mockWindow
      .setSearch(
        `?state=state&id_token=${idToken}&access_token=at&expires_in=600&scope=openid`
      )
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage });

    await instance.processCallback();

    storage.expectCallbackStateRemoved();

    const session = await instance.getSession();

    expect(session).toBeDefined();
    expect(session?.user).toBeDefined();
    expect(session?.user.sub).toBe('some');

    expect(session?.refreshToken).toBeUndefined();
    expect(session?.idToken).toBe(idToken);

    expect(session?.accessTokens).toHaveLength(1);
    expect(session?.accessTokens?.[0].accessToken).toBe('at');
    expect(
      session?.accessTokens?.[0].accessTokenExpiration
    ).toBeLessThanOrEqual(now() + 600);

    fetchSpy.assert();
  });

  it('Redirect Mode - should throw an error if states mismatch', async () => {
    mockWindow
      .setSearch('?state=states&code=code')
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      codeVerifier: 'codeVerifier',
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage });

    const processPromise = instance.processCallback();

    await expect(processPromise).rejects.toThrow(MonoCloudValidationError);
    await expect(processPromise).rejects.toThrow(
      'Sign in callback states mismatch'
    );

    storage.expectCallbackStateRemoved();
  });

  it('Redirect Mode - should throw an op error if callback contains error', async () => {
    mockWindow
      .setSearch(
        '?error=some_error&error_description=Bad%20Request&state=state'
      )
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      codeVerifier: 'codeVerifier',
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage });

    const processPromise = instance.processCallback();

    await expect(processPromise).rejects.toThrow(MonoCloudOPError);
    await expect(processPromise).rejects.toMatchObject({
      error: 'some_error',
      errorDescription: 'Bad Request',
    });

    storage.expectCallbackStateRemoved();
  });

  it('Redirect Mode - should throw an error if jwks fetch fails for implicit id token validation', async () => {
    const idToken = await generateIdToken({ nonce: 'nonce' });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks({ responseCode: 400 })
      .createSpy();

    mockWindow
      .setSearch(`?state=state&id_token=${idToken}`)
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage });

    await expect(instance.processCallback()).rejects.toThrow(
      'Error while fetching JWKS. Unexpected status code: 400'
    );

    storage.expectCallbackStateRemoved();
    fetchSpy.assert();
  });

  it('Redirect Mode - should throw an error if id token is invalid', async () => {
    fetchBuilder().configureMetadata().configureJwks().createSpy();

    mockWindow
      .setSearch('?state=state&id_token=malformed_token_string')
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage });

    const processPromise = instance.processCallback();

    await expect(processPromise).rejects.toThrow(MonoCloudTokenError);
    await expect(processPromise).rejects.toThrow(
      'ID Token must have a header, payload and signature'
    );

    storage.expectCallbackStateRemoved();
  });

  it('Redirect Mode - should extract user from id token even if validate id token is false', async () => {
    const idToken = await generateIdToken({
      claims: {
        only: 'found in',
        decode: true,
      },
    });

    mockWindow
      .setSearch(`?state=state&id_token=${idToken}`)
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage, validateIdToken: false });

    await instance.processCallback();

    storage.expectCallbackStateRemoved();

    const session = await instance.getSession();

    expect(session?.user).toEqual({
      aud: 'clientId',
      exp: expect.any(Number),
      iat: expect.any(Number),
      iss: 'https://example.com',
      only: 'found in',
      sub: 'sub',
      decode: true,
      sub_jwk: expect.any(Object),
    });
  });

  it('Redirect Mode - should throw an error if id token is invalid and validateIdToken is false', async () => {
    mockWindow
      .setSearch('?state=state&id_token=id_token')
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage, validateIdToken: false });

    const processPromise = instance.processCallback();

    await expect(processPromise).rejects.toThrow(MonoCloudTokenError);
    await expect(processPromise).rejects.toThrow(
      'JWT does not contain payload'
    );

    storage.expectCallbackStateRemoved();
  });

  it('Redirect Mode - should throw an error if userinfo returned an error', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureUserinfo({ responseCode: 400 })
      .createSpy();

    mockWindow
      .setSearch('?state=state&access_token=at&scope=openid')
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage, validateIdToken: false });

    const processPromise = instance.processCallback();

    await expect(processPromise).rejects.toThrow(MonoCloudHttpError);
    await expect(processPromise).rejects.toThrow(
      'Error while fetching userinfo. Unexpected status code: 400'
    );

    storage.expectCallbackStateRemoved();
    fetchSpy.assert();
  });

  it('Redirect Mode - should throw an error if code exchange fails', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        responseCode: 500,
        body: 'grant_type=authorization_code&code=code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_verifier=codeVerifier',
      })
      .createSpy();

    mockWindow
      .setSearch('?state=state&code=code')
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      codeVerifier: 'codeVerifier',
      nonce: 'nonce',
      state: 'state',
      mode: 'redirect',
      scopes: 'openid',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage });

    const processPromise = instance.processCallback();

    await expect(processPromise).rejects.toThrow(MonoCloudHttpError);
    await expect(processPromise).rejects.toThrow(
      'Error while performing token grant. Unexpected status code: 500'
    );

    storage.expectCallbackStateRemoved();
    fetchSpy.assert();
  });

  it('Popup Mode - should send the redirect callback through window.postMessage', async () => {
    fetchBuilder().createSpy();

    mockWindow
      .mockPostMessage()
      .mockParentSide('popup')
      .setSearch('?state=state&code=code')
      .setPathname('/callback')
      .assert();

    const instance = testInstance({ storage });

    await instance.processCallback();

    expect(window.fetch).not.toHaveBeenCalled();

    await vi.waitFor(() => {
      expect(mockWindow.parentPostMessage).toHaveBeenCalledWith(
        expect.objectContaining({
          source: 'monocloud-auth-js-core',
          url: 'http://localhost:3000/callback?state=state&code=code',
        }),
        'http://localhost:3000'
      );
    });
  });

  it('Popup Mode - should throw an error if states mismatch', async () => {
    fetchBuilder().configureMetadata().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({
      storage,
    });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    expect(window.open).toHaveBeenCalledWith(
      'about:blank',
      'mc.popup',
      expect.any(String)
    );

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: 'http://localhost:3000/callback?state=WRONG_STATE&code=code',
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signInPromise).rejects.toThrow(MonoCloudValidationError);
    await expect(signInPromise).rejects.toThrow(
      'Sign in callback states mismatch'
    );

    expect(mockPopup.close).toHaveBeenCalled();
  });

  it('Popup Mode - should throw an error if callback contains error', async () => {
    fetchBuilder().configureMetadata().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({
      storage,
    });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const url = new URL(mockPopup.location.href);
    const generatedState = url.searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000/callback?error=access_denied&error_description=User+denied&state=${generatedState}`,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signInPromise).rejects.toThrow(MonoCloudOPError);
    await expect(signInPromise).rejects.toMatchObject({
      error: 'access_denied',
      errorDescription: 'User denied',
    });

    expect(mockPopup.close).toHaveBeenCalled();
  });

  it('Popup Mode - should throw an error if jwks fetch fails for implicit id token validation', async () => {
    const idToken = await generateIdToken({ nonce: 'nonce' });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks({ responseCode: 400 })
      .createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({
      storage,
    });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const url = new URL(mockPopup.location.href);
    const generatedState = url.searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000/callback?state=${generatedState}&id_token=${idToken}`,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signInPromise).rejects.toThrow(MonoCloudHttpError);
    await expect(signInPromise).rejects.toThrow(
      'Error while fetching JWKS. Unexpected status code: 400'
    );

    expect(mockPopup.close).toHaveBeenCalled();
    fetchSpy.assert();
  });

  it('Popup Mode - should throw an error if id token is invalid', async () => {
    fetchBuilder().configureMetadata().configureJwks().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({
      storage,
    });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const url = new URL(mockPopup.location.href);
    const generatedState = url.searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000/callback?state=${generatedState}&id_token=malformed_token_string`,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signInPromise).rejects.toThrow(MonoCloudTokenError);
    await expect(signInPromise).rejects.toThrow(
      'ID Token must have a header, payload and signature'
    );

    expect(mockPopup.close).toHaveBeenCalled();
  });

  it('Popup Mode - should extract user from id token even if validate id token is false', async () => {
    const idToken = await generateIdToken({
      claims: {
        only: 'found in',
        decode: true,
      },
    });

    const windowFetchSpy = vi.spyOn(window, 'fetch');
    fetchBuilder().configureMetadata().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({
      storage,
      validateIdToken: false,
    });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const url = new URL(mockPopup.location.href);
    const generatedState = url.searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000/callback?state=${generatedState}&id_token=${idToken}`,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await signInPromise;

    storage.expectSession(
      expect.objectContaining({
        idToken,
        user: expect.objectContaining({
          iss: 'https://example.com',
          sub: 'sub',
          aud: 'clientId',
          only: 'found in',
          decode: true,
        }),
      })
    );

    expect(mockPopup.close).toHaveBeenCalled();

    expect(windowFetchSpy).toHaveBeenCalledTimes(1);
    expect(windowFetchSpy.mock.calls[0][0]).toContain(
      '.well-known/openid-configuration'
    );
  });

  it('Popup Mode - should throw an error if id token is invalid and validateIdToken is false', async () => {
    fetchBuilder().configureMetadata().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({
      storage,
      validateIdToken: false,
    });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const url = new URL(mockPopup.location.href);
    const generatedState = url.searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000/callback?state=${generatedState}&id_token=malformed_token_string`,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signInPromise).rejects.toThrow(MonoCloudTokenError);
    await expect(signInPromise).rejects.toThrow('JWT does not contain payload');

    expect(mockPopup.close).toHaveBeenCalled();
    storage.expectNoSession();
  });

  it('Popup Mode - should throw an error if userinfo returned an error', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureUserinfo({ responseCode: 400 })
      .createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({
      storage,
      responseType: 'token',
    });

    const signInPromise = instance.signIn({
      mode: 'popup',
      scopes: 'openid profile',
    });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const url = new URL(mockPopup.location.href);
    const generatedState = url.searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000/callback#state=${generatedState}&access_token=at&token_type=Bearer&expires_in=3600&scope=openid%20profile`,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signInPromise).rejects.toThrow(MonoCloudHttpError);
    await expect(signInPromise).rejects.toThrow(
      'Error while fetching userinfo. Unexpected status code: 400'
    );

    expect(mockPopup.close).toHaveBeenCalled();
    storage.expectNoSession();
    fetchSpy.assert();
  });

  it('Popup Mode - should throw an error if code exchange fails', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        responseCode: 500,
      })
      .createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({ storage });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const authorizeUrl = new URL(mockPopup.location.href);
    const generatedState = authorizeUrl.searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000/callback?state=${encodeURIComponent(
            generatedState ?? ''
          )}&code=test-auth-code`,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signInPromise).rejects.toThrow(MonoCloudHttpError);
    await expect(signInPromise).rejects.toThrow(
      'Error while performing token grant. Unexpected status code: 500'
    );

    await vi.waitFor(() => {
      expect(mockPopup.close).toHaveBeenCalled();
    });

    storage.expectNoSession();
    fetchSpy.assert();
  });

  it('Popup Mode - should redirect popup to sign in page and resolve when a session message is received', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({ storage, validateIdToken: false });

    const signinPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(async () => {
      expect(mockPopup.location.href).toMatch(urlRegex);
      expect(await instance.getSession()).toBeUndefined();
    });

    const authorizeUrl = new URL(mockPopup.location.href);
    const generatedState = authorizeUrl.searchParams.get('state');
    const generatedNonce = authorizeUrl.searchParams.get('nonce');

    const idToken = await generateIdToken({
      nonce: generatedNonce ?? undefined,
      claims: { email: 'test@example.com' },
    });

    fetchSpy
      .configureTokenEndpoint({
        accessToken: 'mock-access-token',
        idToken,
      })
      .configureUserinfo({
        accessToken: 'mock-access-token',
        claims: { sub: 'sub', email: 'test@example.com' },
      });

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000/callback?code=auth-code&state=${generatedState}`,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signinPromise).resolves.toBeUndefined();

    const expectedSession = expect.objectContaining({
      accessTokens: [
        expect.objectContaining({
          accessToken: 'mock-access-token',
        }),
      ],
      refreshToken: expect.any(String),
      idToken: expect.any(String),
      user: expect.objectContaining({
        sub: 'sub',
        email: 'test@example.com',
      }),
    });

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();

      storage.expectSession(expectedSession);

      const savedSession = await instance.getSession();
      expect(savedSession).toEqual(expectedSession);
    });

    fetchSpy.assert();
  });

  it('Popup Mode - should redirect popup to sign in page and reject when an error message is received', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({ storage });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const authorizeUrl = new URL(mockPopup.location.href);
    const generatedState = authorizeUrl.searchParams.get('state');

    const callbackUrl =
      `http://localhost:3000/callback` +
      `?error=some_error` +
      `&error_description=${encodeURIComponent('something went wrong')}` +
      `&state=${encodeURIComponent(generatedState ?? '')}`;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: callbackUrl,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signInPromise).rejects.toMatchObject({
      error: 'some_error',
      errorDescription: 'something went wrong',
    });

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();

      storage.expectNoSession();
      expect(await instance.getSession()).toBeUndefined();

      fetchSpy.assert();
    });
  });

  it('Popup Mode - can timeout', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({ storage, authWindowTimeout: 0.1 });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(async () => {
      expect(mockPopup.location.href).toMatch(urlRegex);
      expect(await instance.getSession()).toBeUndefined();
    });

    await expect(signInPromise).rejects.toThrow(MonoCloudJsError);
    await expect(signInPromise).rejects.toThrow('Window timed out');

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();
      expect(await instance.getSession()).toBeUndefined();
      fetchSpy.assert();
    });
  });

  it('Popup Mode - should throw error if popup fails to open', async () => {
    vi.spyOn(window, 'open').mockReturnValue(null);

    const instance = testInstance({ storage });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await expect(signInPromise).rejects.toThrow(MonoCloudJsError);
    await expect(signInPromise).rejects.toThrow('Could not open popup');

    expect(await instance.getSession()).toBeUndefined();
  });

  it('Popup Mode - throws when user closes the window', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    };

    vi.spyOn(window, 'open').mockReturnValue(mockPopup as unknown as Window);

    const instance = testInstance({ storage });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(window.open).toHaveBeenCalled();
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    mockPopup.closed = true;

    await expect(signInPromise).rejects.toThrow(MonoCloudJsError);
    await expect(signInPromise).rejects.toThrow('Window closed by user');

    await vi.waitFor(async () => {
      expect(await instance.getSession()).toBeUndefined();
    });

    fetchSpy.assert();
  });

  it('Popup Mode - should only resolve the promise if the origin is appUrl', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({ storage });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const authorizeUrl = new URL(mockPopup.location.href);
    const state = authorizeUrl.searchParams.get('state');
    const nonce = authorizeUrl.searchParams.get('nonce');

    const idToken = await generateIdToken({
      nonce: nonce ?? undefined,
      claims: { email: 'test@example.com' },
    });

    fetchSpy
      .configureTokenEndpoint({
        accessToken: 'mock-access-token',
        idToken,
      })
      .configureUserinfo({
        accessToken: 'mock-access-token',
        claims: { sub: 'sub', email: 'test@example.com' },
      });

    const goodCallbackUrl = `http://localhost:3000/callback?code=auth-code&state=${encodeURIComponent(
      state ?? ''
    )}`;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: goodCallbackUrl,
        },
        source: mockPopup,
        origin: 'https://hackersite.com',
      })
    );

    await vi.waitFor(() => {
      expect(mockPopup.close).not.toHaveBeenCalled();
    });

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: goodCallbackUrl,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signInPromise).resolves.toBeUndefined();

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();

      const saved = await instance.getSession();
      expect(saved).toEqual(
        expect.objectContaining({
          accessTokens: [
            expect.objectContaining({
              accessToken: 'mock-access-token',
            }),
          ],
          user: expect.objectContaining({
            sub: 'sub',
            email: 'test@example.com',
          }),
        })
      );
    });

    fetchSpy.assert();
  });

  it('Popup Mode - should only resolve the promise if the source is popup window', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({ storage });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const authorizeUrl = new URL(mockPopup.location.href);
    const state = authorizeUrl.searchParams.get('state');
    const nonce = authorizeUrl.searchParams.get('nonce');

    const idToken = await generateIdToken({
      nonce: nonce ?? undefined,
      claims: { email: 'test@example.com' },
    });

    fetchSpy
      .configureTokenEndpoint({
        accessToken: 'mock-access-token',
        idToken,
      })
      .configureUserinfo({
        accessToken: 'mock-access-token',
        claims: { sub: 'sub', email: 'test@example.com' },
      });

    const callbackUrl = `http://localhost:3000/callback?code=auth-code&state=${encodeURIComponent(
      state ?? ''
    )}`;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: callbackUrl,
        },
        source: null as unknown as Window,
        origin: 'http://localhost:3000',
      })
    );

    await vi.waitFor(() => {
      expect(mockPopup.close).not.toHaveBeenCalled();
    });

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: callbackUrl,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signInPromise).resolves.toBeUndefined();

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();

      const saved = await instance.getSession();
      expect(saved).toEqual(
        expect.objectContaining({
          accessTokens: [
            expect.objectContaining({
              accessToken: 'mock-access-token',
            }),
          ],
          user: expect.objectContaining({
            sub: 'sub',
            email: 'test@example.com',
          }),
        })
      );
    });

    fetchSpy.assert();
  });

  it('Popup Mode - should only resolve the promise if data.source is monocloud-auth-js-core', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({ storage });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const authorizeUrl = new URL(mockPopup.location.href);
    const state = authorizeUrl.searchParams.get('state');
    const nonce = authorizeUrl.searchParams.get('nonce');

    const idToken = await generateIdToken({
      nonce: nonce ?? undefined,
      claims: { email: 'test@example.com' },
    });

    fetchSpy
      .configureTokenEndpoint({
        accessToken: 'mock-access-token',
        idToken,
      })
      .configureUserinfo({
        accessToken: 'mock-access-token',
        claims: { sub: 'sub', email: 'test@example.com' },
      });

    const callbackUrl = `http://localhost:3000/callback?code=auth-code&state=${encodeURIComponent(
      state ?? ''
    )}`;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'someoneelse',
          url: callbackUrl,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await vi.waitFor(() => {
      expect(mockPopup.close).not.toHaveBeenCalled();
    });

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: callbackUrl,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signInPromise).resolves.toBeUndefined();

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();

      const saved = await instance.getSession();
      expect(saved).toEqual(
        expect.objectContaining({
          accessTokens: [
            expect.objectContaining({
              accessToken: 'mock-access-token',
            }),
          ],
          user: expect.objectContaining({
            sub: 'sub',
            email: 'test@example.com',
          }),
        })
      );
    });

    fetchSpy.assert();
  });

  it('should throw error when callbackUrl origin/path does not match redirectUri', async () => {
    const instance = testInstance({ storage });

    const callbackState: CallbackState = {
      mode: 'popup',
      state: 'state',
      scopes: 'openid',
    };

    const badCallbackUrl =
      'http://localhost:3000/wrong-callback?code=code&state=state';

    const p = (instance as any).processSignInCallback(
      badCallbackUrl,
      callbackState
    );

    await expect(p).rejects.toThrow(MonoCloudValidationError);
    await expect(p).rejects.toThrow('Incorrect callback url');
  });

  it('should throw error when callbackState.signOut is true', async () => {
    const instance = testInstance({ storage });

    const callbackState: CallbackState = {
      mode: 'popup',
      state: 'state',
      scopes: 'openid',
      signOut: true,
    };

    const callbackUrl = 'http://localhost:3000/callback?code=code&state=state';

    const p = (instance as any).processSignInCallback(
      callbackUrl,
      callbackState
    );

    await expect(p).rejects.toThrow(MonoCloudValidationError);
    await expect(p).rejects.toThrow('Incorrect callback state');
  });

  it('should throw error when callbackState.scopes is missing', async () => {
    const instance = testInstance({ storage });

    const callbackState = {
      mode: 'popup',
      state: 'state',
    } as unknown as CallbackState;

    const callbackUrl = 'http://localhost:3000/callback?code=code&state=state';

    const p = (instance as any).processSignInCallback(
      callbackUrl,
      callbackState
    );

    await expect(p).rejects.toThrow(MonoCloudValidationError);
    await expect(p).rejects.toThrow('Scopes missing from callback state');
  });

  it('should throw error when callback contains no code/token/error', async () => {
    const instance = testInstance({ storage });

    const callbackState: CallbackState = {
      mode: 'popup',
      state: 'state',
      scopes: 'openid',
    };

    const callbackUrl = 'http://localhost:3000/callback?state=state';

    const p = (instance as any).processSignInCallback(
      callbackUrl,
      callbackState
    );

    await expect(p).rejects.toThrow(MonoCloudValidationError);
    await expect(p).rejects.toThrow('No parameters found in callback');
  });

  it('should combine multiple resources and scopes from options.resources', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();
    mockWindow.assert();

    const instance = testInstance({
      storage,
      resources: [
        { resource: 'api://inventory', scopes: 'inv:read' },
        { resource: 'api://orders', scopes: 'orders:write' },
      ],
    });

    await instance.signIn();

    expect(window.location.assign).toHaveBeenCalledOnce();

    const [calledUrl] = (window.location.assign as any).mock.calls[0];
    const url = new URL(calledUrl);

    const resources = url.searchParams.getAll('resource');

    expect(resources).toHaveLength(2);
    expect(resources).toContain('api://inventory');
    expect(resources).toContain('api://orders');

    const scopes = url.searchParams.get('scope')?.split(' ') ?? [];
    expect(scopes).toContain('inv:read');
    expect(scopes).toContain('orders:write');

    fetchSpy.assert();
  });

  it('should filter out invalid resources and scopes from options.resources', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();
    mockWindow.assert();

    const instance = testInstance({
      storage,
      resources: [
        { resource: 'valid-resource', scopes: 'valid-scope' },
        { resource: '', scopes: '' },
        { resource: undefined, scopes: undefined },
        {} as any,
        { resource: null as any, scopes: null as any },
      ],
    });

    await instance.signIn();

    expect(window.location.assign).toHaveBeenCalledOnce();

    const [calledUrl] = (window.location.assign as any).mock.calls[0];
    const url = new URL(calledUrl);

    const resources = url.searchParams.get('resource')?.split(' ') ?? [];
    expect(resources).toContain('valid-resource');
    expect(resources).not.toContain('');
    expect(resources).not.toContain('undefined');
    expect(resources).not.toContain('null');
    expect(resources.length).toBe(1);

    const scopes = url.searchParams.get('scope')?.split(' ') ?? [];
    expect(scopes).toContain('valid-scope');
    expect(scopes).not.toContain('');
    expect(scopes).not.toContain('undefined');
    expect(scopes).not.toContain('null');

    fetchSpy.assert();
  });

  it('should handle corrupted/invalid JSON in session storage for callback state', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    vi.spyOn(window.sessionStorage, 'getItem').mockReturnValue(
      '{ malformed_json_string'
    );

    const removeItemSpy = vi.spyOn(window.sessionStorage, 'removeItem');

    const instance = testInstance({ storage });

    const processPromise = instance.processCallback();

    await expect(processPromise).rejects.toThrow(SyntaxError);

    expect(removeItemSpy).toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalledWith(
      'Unexpected error reading callback state:'
    );

    consoleSpy.mockRestore();
  });

  it('Popup Mode - should ignore messages with invalid data types or missing URLs', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({ storage });

    const signInPromise = instance.signIn({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const authorizeUrl = new URL(mockPopup.location.href);
    const generatedState = authorizeUrl.searchParams.get('state');
    const generatedNonce = authorizeUrl.searchParams.get('nonce');
    const idToken = await generateIdToken({
      nonce: generatedNonce ?? undefined,
      claims: { email: 'test@example.com' },
    });

    fetchSpy
      .configureTokenEndpoint({ accessToken: 'at', idToken })
      .configureUserinfo({ claims: { sub: 'sub' } });

    window.dispatchEvent(
      new MessageEvent('message', {
        data: 'invalid-string-data',
        origin: 'http://localhost:3000',
        source: mockPopup,
      })
    );

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          otherProp: 123,
        },
        origin: 'http://localhost:3000',
        source: mockPopup,
      })
    );

    const validCallbackUrl = `http://localhost:3000/callback?code=auth-code&state=${encodeURIComponent(
      generatedState ?? ''
    )}`;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: validCallbackUrl,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signInPromise).resolves.not.toThrow();

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();
      fetchSpy.assert();
    });
  });

  it('should fall back to window.parent when window.opener is null', async () => {
    const mockParent = {
      postMessage: vi.fn(),
    };

    vi.spyOn(window, 'opener', 'get').mockReturnValue(null);
    vi.spyOn(window, 'parent', 'get').mockReturnValue(
      mockParent as unknown as Window
    );
    vi.spyOn(window, 'top', 'get').mockReturnValue(
      mockParent as unknown as Window
    );

    mockWindow.setPathname('/callback').assert();

    const instance = testInstance({ storage });

    await instance.processCallback();

    expect(mockParent.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        source: 'monocloud-auth-js-core',
        url: expect.stringContaining('/callback'),
      }),
      'http://localhost:3000'
    );
  });
});
