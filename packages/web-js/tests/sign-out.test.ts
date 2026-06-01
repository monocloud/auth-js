// eslint-disable-next-line import/no-extraneous-dependencies
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { MonoCloudSession } from '@monocloud/auth-core';
import { fetchBuilder, MockWindow } from '@monocloud/auth-test-utils';
import { now } from '@monocloud/auth-core/internal';
import { testInstance, setSession, VanillaJsMockStorage } from './utils';
import {
  CallbackState,
  MonoCloudJsError,
  MonoCloudValidationError,
} from '../src';

describe('signOut() Tests', () => {
  let mockWindow: MockWindow;
  let mockStorage: VanillaJsMockStorage;

  beforeEach(() => {
    mockWindow = new MockWindow();
    mockStorage = new VanillaJsMockStorage();
  });

  afterEach(() => {
    mockWindow.restore();
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it('Redirect Mode - should set custom redirect uri from options (with trailing slash trimmed)', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow
      .expectQuery(
        'post_logout_redirect_uri',
        'http://localhost:3000/signout/custom'
      )
      .assert();

    const instance = testInstance({ storage: mockStorage });

    instance.signOut({
      postLogoutRedirectUri: 'http://localhost:3000/signout/custom/',
    });

    await vi.waitFor(() => {
      expect(window.location.assign).toHaveBeenCalledOnce();
      fetchSpy.assert();
    });
  });

  it('Redirect Mode - should throw a federated sign-out from inside an iframe and not clear the session', async () => {
    mockWindow.mockParentSide('silent').assert();

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [],
      authorizedScopes: 'openid',
    };

    await setSession(mockStorage, session);

    const instance = testInstance({ storage: mockStorage });

    const error = await instance
      .signOut({ federatedSignOut: true })
      .catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudJsError);
    expect(error.message).toContain(
      'Cannot start a redirect sign-out from inside an iframe'
    );
    expect(window.location.assign).not.toHaveBeenCalled();

    mockStorage.expectSession(session);
    expect(await instance.getSession()).toEqual(session);
  });

  it('should not throw a non-federated sign-out from inside an iframe', async () => {
    mockWindow.mockParentSide('silent').assert();

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [],
      authorizedScopes: 'openid',
    };

    await setSession(mockStorage, session);

    const instance = testInstance({ storage: mockStorage });

    await expect(
      instance.signOut({ federatedSignOut: false })
    ).resolves.toBeUndefined();

    expect(window.location.assign).not.toHaveBeenCalled();
    mockStorage.expectNoSession();
  });

  it('should redirect to signout with the root post logout redirect uri (and state) when signOutPath is not set', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow
      .expectQuery('client_id', 'clientId')
      .expectQueryKey('state')
      .expectQuery('post_logout_redirect_uri', 'http://localhost:3000')
      .doNotExpectQueryKey('id_token_hint')
      .assert();

    const instance = testInstance({
      storage: mockStorage,
      signOutPath: undefined,
    });

    instance.signOut();

    await vi.waitFor(() => {
      expect(window.location.assign).toHaveBeenCalledOnce();
      fetchSpy.assert();
    });
  });

  it('should redirect to signout with the root post logout redirect uri (and state) when signOutPath is not set (Session Present)', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow
      .expectQuery('client_id', 'clientId')
      .expectQueryKey('state')
      .expectQuery('post_logout_redirect_uri', 'http://localhost:3000')
      .doNotExpectQueryKey('id_token_hint')
      .assert();

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'token',
          requestedScopes: 'token',
          accessTokenExpiration: now() + 1000,
        },
      ],
      authorizedScopes: 'token',
    };

    await setSession(mockStorage, session);

    const instance = testInstance({
      storage: mockStorage,
      signOutPath: undefined,
    });

    expect(await instance.getSession()).toBeDefined();

    instance.signOut();

    await vi.waitFor(async () => {
      expect(window.location.assign).toHaveBeenCalledOnce();
      expect(await instance.getSession()).toBeUndefined();
      fetchSpy.assert();
    });
  });

  it('Redirect Mode - should redirect to the sign out page', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow
      .expectOrigin('https://example.com/connect/endsession')
      .expectQueryKey('state')
      .expectQuery('client_id', 'clientId')
      .expectQuery('post_logout_redirect_uri', 'http://localhost:3000/signout')
      .assert();

    const instance = testInstance({ storage: mockStorage });

    instance.signOut();

    await vi.waitFor(() => {
      expect(window.location.assign).toHaveBeenCalledWith(
        expect.stringContaining('https://example.com/connect/endsession')
      );
      mockStorage
        .expectCallbackState()
        .expectCallbackStateState()
        .expectCallbackStateMode('redirect')
        .expectCallbackStateSignOut(true);
      fetchSpy.assert();
    });
  });

  it('Redirect Mode - should process signout callback', async () => {
    mockWindow.setSearch('?state=state').setPathname('/signout').assert();

    const state: CallbackState = {
      mode: 'redirect',
      signOut: true,
      state: 'state',
    };

    mockStorage.setCallbackState(state);

    const instance = testInstance({
      storage: mockStorage,
      signOutPath: '/signout',
    });

    instance.processCallback();

    await vi.waitFor(() => {
      mockStorage.expectCallbackStateRemoved();
    });
  });

  it('Redirect Mode - should process signout callback even if the signOutPath is not set', async () => {
    mockWindow.setSearch('?state=state').setPathname('/').assert();

    const state: CallbackState = {
      mode: 'redirect',
      signOut: true,
      state: 'state',
    };

    mockStorage.setCallbackState(state);

    const instance = testInstance({
      storage: mockStorage,
      signOutPath: undefined,
    });

    instance.processCallback();

    await vi.waitFor(() => {
      mockStorage.expectCallbackStateRemoved();
    });
  });

  it('Redirect Mode - should process signout callback with signOutPath without leading slash', async () => {
    mockWindow.setSearch('?state=state').setPathname('/signout').assert();

    const state: CallbackState = {
      mode: 'redirect',
      signOut: true,
      state: 'state',
    };

    mockStorage.setCallbackState(state);

    const instance = testInstance({
      storage: mockStorage,
      signOutPath: 'signout',
    });

    instance.processCallback();

    await vi.waitFor(() => {
      mockStorage.expectCallbackStateRemoved();
    });
  });

  it('Redirect Mode - should set an error if states mismatch', async () => {
    mockWindow.setSearch('?state=state').setPathname('/signout').assert();

    const state: CallbackState = {
      mode: 'redirect',
      signOut: true,
      state: 'states',
    };

    mockStorage.setCallbackState(state);

    const instance = testInstance({ storage: mockStorage });

    const error = await instance.processCallback().catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudValidationError);
    expect(error.message).toBe('Sign out states mismatch');

    await vi.waitFor(() => {
      mockStorage.expectCallbackStateRemoved();
    });
  });

  it('Popup Mode - should process signout callback', async () => {
    mockWindow
      .mockPostMessage()
      .mockParentSide('popup')
      .setSearch('?state=state')
      .setPathname('/signout')
      .assert();

    const state: CallbackState = {
      mode: 'popup',
      signOut: true,
      state: 'state',
    };

    mockStorage.setCallbackState(state);

    const instance = testInstance({
      storage: mockStorage,
      signOutPath: '/signout',
    });

    instance.processCallback();

    await vi.waitFor(() => {
      expect(mockWindow.parentPostMessage).toHaveBeenCalledWith(
        expect.objectContaining({
          source: 'monocloud-auth-web-js',
          url: 'http://localhost:3000/signout?state=state',
        }),
        'http://localhost:3000'
      );
    });
  });

  it('Popup Mode - should throw error if states mismatch', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({
      storage: mockStorage,
      signOutPath: '/signout',
    });

    const signOutPromise = instance.signOut({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toContain(
        'https://example.com/connect/endsession'
      );
    });

    expect(window.open).toHaveBeenCalledWith(
      'about:blank',
      'mc.popup',
      expect.any(String)
    );

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url: 'http://localhost:3000/signout?state=wrong-state',
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    const error = await signOutPromise.catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudValidationError);
    expect(error.message).toBe('Sign out states mismatch');
    fetchSpy.assert();
    expect(mockPopup.close).toHaveBeenCalled();
  });

  it('Popup Mode - should redirect popup to sign out page and resolve when a success message is received', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({
      storage: mockStorage,
      signOutPath: undefined,
    });

    const signOutPromise = instance.signOut({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toContain(
        'https://example.com/connect/endsession'
      );
    });

    expect(window.open).toHaveBeenCalledWith(
      'about:blank',
      'mc.popup',
      expect.any(String)
    );

    const state = new URL(mockPopup.location.href).searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url: `http://localhost:3000?state=${state}`,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signOutPromise).resolves.toBeUndefined();

    await vi.waitFor(() => {
      fetchSpy.assert();
      expect(mockPopup.close).toHaveBeenCalled();
      mockStorage.expectCallbackStateRemoved();
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

    const instance = testInstance({
      storage: mockStorage,
      authWindowTimeout: 0.1,
    });

    const error = await instance.signOut({ mode: 'popup' }).catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudJsError);
    expect(error.message).toBe('Authentication window timed out');

    expect(mockPopup.close).toHaveBeenCalled();

    expect(window.open).toHaveBeenCalledWith(
      'about:blank',
      'mc.popup',
      expect.any(String)
    );

    expect(mockPopup.location.href).toContain(
      'https://example.com/connect/endsession'
    );

    fetchSpy.assert();
  });

  it('Popup Mode - should throw error if popup fails to open', async () => {
    const fetchSpy = fetchBuilder().createSpy();

    vi.spyOn(window, 'open').mockReturnValue(null);

    const instance = testInstance({ storage: mockStorage });

    const error = await instance.signOut({ mode: 'popup' }).catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudJsError);
    expect(error.message).toBe('Could not open popup');

    fetchSpy.assert();
    mockStorage.expectCallbackStateRemoved();
  });

  it('Popup Mode - throws when user closes the window', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    };

    vi.spyOn(window, 'open').mockReturnValue(mockPopup as unknown as Window);

    const instance = testInstance({ storage: mockStorage });

    const signOutPromise = instance.signOut({ mode: 'popup' });

    setTimeout(() => {
      mockPopup.closed = true;
    }, 200);

    const error = await signOutPromise.catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudJsError);
    expect(error.message).toBe('Window closed by user');

    fetchSpy.assert();
  });

  it('Popup Mode - clears local session up-front so a cancelled popup does not strand the app signed-in', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    };

    vi.spyOn(window, 'open').mockReturnValue(mockPopup as unknown as Window);

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
      idToken: 'idToken',
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid',
          requestedScopes: 'openid',
        },
      ],
      authorizedScopes: 'openid',
    };

    await setSession(mockStorage, existingSession);

    const instance = testInstance({ storage: mockStorage });

    expect(await instance.getSession()).toEqual(existingSession);

    const signOutPromise = instance.signOut({ mode: 'popup' });

    setTimeout(() => {
      mockPopup.closed = true;
    }, 200);

    const error = await signOutPromise.catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudJsError);
    expect(error.message).toBe('Window closed by user');

    expect(await instance.getSession()).toBeUndefined();

    fetchSpy.assert();
  });

  it('Popup Mode - should only resolve the promise if the origin is appUrl', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({
      storage: mockStorage,
      signOutPath: undefined,
    });

    const signOutPromise = instance.signOut({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toContain(
        'https://example.com/connect/endsession'
      );
    });

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url: `http://localhost:3000`,
        },
        source: mockPopup,
        origin: 'http://yyy.com',
      })
    );

    expect(mockPopup.close).not.toHaveBeenCalled();

    const state = new URL(mockPopup.location.href).searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url: `http://localhost:3000?state=${state}`,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signOutPromise).resolves.toBeUndefined();

    await vi.waitFor(() => {
      fetchSpy.assert();
      expect(mockPopup.close).toHaveBeenCalled();
    });
  });

  it('Popup Mode - should only resolve the promise if the source is the expected popup window', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    };

    vi.spyOn(window, 'open').mockReturnValue(mockPopup as unknown as Window);

    const instance = testInstance({
      storage: mockStorage,
      signOutPath: undefined,
    });

    expect(await instance.getSession()).toBeUndefined();

    const signOutPromise = instance.signOut({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toContain(
        'https://example.com/connect/endsession'
      );
    });

    const randomWindow = {} as Window;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url: `http://localhost:3000`,
        },
        source: randomWindow,
        origin: 'http://localhost:3000',
      })
    );

    expect(mockPopup.close).not.toHaveBeenCalled();

    const state = new URL(mockPopup.location.href).searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url: `http://localhost:3000?state=${state}`,
        },
        source: mockPopup as unknown as Window,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signOutPromise).resolves.toBeUndefined();

    await vi.waitFor(() => {
      fetchSpy.assert();
      expect(mockPopup.close).toHaveBeenCalled();
    });
  });

  it('Popup Mode - should only resolve the promise if data.source is the expected SDK identifier', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    };

    vi.spyOn(window, 'open').mockReturnValue(mockPopup as unknown as Window);

    const instance = testInstance({
      storage: mockStorage,
      signOutPath: undefined,
    });

    expect(await instance.getSession()).toBeUndefined();

    const signOutPromise = instance.signOut({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toContain(
        'https://example.com/connect/endsession'
      );
    });

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'yyy',
          url: `http://localhost:3000`,
        },
        source: mockPopup as unknown as Window,
        origin: 'http://localhost:3000',
      })
    );

    expect(mockPopup.close).not.toHaveBeenCalled();

    const state = new URL(mockPopup.location.href).searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url: `http://localhost:3000?state=${state}`,
        },
        source: mockPopup as unknown as Window,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signOutPromise).resolves.toBeUndefined();

    await vi.waitFor(() => {
      fetchSpy.assert();
      expect(mockPopup.close).toHaveBeenCalled();
    });
  });

  it('should only clear local session and return if federatedSignOut is false', async () => {
    fetchBuilder().createSpy();
    vi.spyOn(window.location, 'assign');
    vi.spyOn(window, 'open');

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'token',
          requestedScopes: 'token',
          accessTokenExpiration: now() + 1000,
        },
      ],
      authorizedScopes: 'token',
    };

    await setSession(mockStorage, session);

    const instance = testInstance({
      storage: mockStorage,
      federatedSignOut: false,
    });

    expect(await instance.getSession()).toBeDefined();

    await instance.signOut();

    expect(await instance.getSession()).toBeUndefined();
    mockStorage.expectNoSession();

    expect(window.fetch).not.toHaveBeenCalled();
  });

  it('should override client-level federatedSignOut when passed per call (true -> false)', async () => {
    fetchBuilder().createSpy();
    vi.spyOn(window.location, 'assign');
    vi.spyOn(window, 'open');

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'token',
          requestedScopes: 'token',
          accessTokenExpiration: now() + 1000,
        },
      ],
      authorizedScopes: 'token',
    };

    await setSession(mockStorage, session);

    const instance = testInstance({
      storage: mockStorage,
      federatedSignOut: true,
    });

    await instance.signOut({ federatedSignOut: false });

    expect(await instance.getSession()).toBeUndefined();
    mockStorage.expectNoSession();
    expect(window.location.assign).not.toHaveBeenCalled();
    expect(window.fetch).not.toHaveBeenCalled();
  });

  it('should override client-level federatedSignOut when passed per call (false -> true)', async () => {
    fetchBuilder().configureMetadata().createSpy();
    mockWindow.expectOrigin('https://example.com/connect/endsession').assert();

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'token',
          requestedScopes: 'token',
          accessTokenExpiration: now() + 1000,
        },
      ],
      authorizedScopes: 'token',
    };

    await setSession(mockStorage, session);

    const instance = testInstance({
      storage: mockStorage,
      federatedSignOut: false,
    });

    await instance.signOut({ federatedSignOut: true });

    expect(await instance.getSession()).toBeUndefined();
    expect(window.location.assign).toHaveBeenCalledWith(
      expect.stringContaining('https://example.com/connect/endsession')
    );
  });

  it('Popup Mode - should clear session immediately even if state validation fails', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'token',
          requestedScopes: 'token',
          accessTokenExpiration: now() + 1000,
        },
      ],
      authorizedScopes: 'token',
    };

    await setSession(mockStorage, session);

    const instance = testInstance({ storage: mockStorage });

    const signOutPromise = instance.signOut({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toContain(
        'https://example.com/connect/endsession'
      );
    });
    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url: 'http://localhost:3000/signout?state=wrong-state',
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signOutPromise).rejects.toThrow('Sign out states mismatch');
    expect(await instance.getSession()).toBeUndefined();
    mockStorage.expectNoSession();

    fetchSpy.assert();
    expect(mockPopup.close).toHaveBeenCalled();
  });

  it('Redirect Mode - should clear session immediately even if state validation fails', async () => {
    mockWindow.setSearch('?state=wrong-state').setPathname('/signout').assert();

    const state: CallbackState = {
      mode: 'redirect',
      signOut: true,
      state: 'correct-state',
    };

    mockStorage.setCallbackState(state);

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'token',
          requestedScopes: 'token',
          accessTokenExpiration: now() + 1000,
        },
      ],
      authorizedScopes: 'token',
    };

    await setSession(mockStorage, session);

    const instance = testInstance({
      storage: mockStorage,
      signOutPath: '/signout',
    });

    expect(await instance.getSession()).toBeDefined();

    const error = await instance.processCallback().catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudValidationError);
    expect(error.message).toBe('Sign out states mismatch');

    await vi.waitFor(async () => {
      expect(await instance.getSession()).toBeUndefined();
      mockStorage.expectNoSession();
      mockStorage.expectCallbackStateRemoved();
    });
  });

  it('should throw error when callbackUrl origin/path does not match redirectUri', async () => {
    const instance = testInstance({ storage: mockStorage });

    const callbackState: CallbackState = {
      mode: 'popup',
      state: 'state',
      scopes: 'openid',
    };

    const badCallbackUrl =
      'http://localhost:3000/wrong-callback?code=code&state=state';

    const error = await (instance as any)
      .internalProcessSignOutCallback(badCallbackUrl, callbackState)
      .catch((e: any) => e);

    expect(error).toBeInstanceOf(MonoCloudValidationError);
    expect(error.message).toBe('Incorrect callback url');
  });

  it('should throw error when callbackState.signOut is false', async () => {
    const instance = testInstance({ storage: mockStorage });

    const callbackState: CallbackState = {
      mode: 'popup',
      state: 'state',
      scopes: 'openid',
      signOut: false,
    };

    const callbackUrl = 'http://localhost:3000/signout?code=code&state=state';

    const error = await (instance as any)
      .internalProcessSignOutCallback(callbackUrl, callbackState)
      .catch((e: any) => e);

    expect(error).toBeInstanceOf(MonoCloudValidationError);
    expect(error.message).toBe('Incorrect callback state');
  });

  it('processCallback - should no-op when callback state is missing', async () => {
    mockWindow.setPathname('/signout').assert();

    const instance = testInstance({ storage: mockStorage });

    await expect(instance.processCallback()).resolves.toBeUndefined();

    mockStorage.expectCallbackStateRemoved().expectNoSession();
  });

  it('processCallback - should no-op on the sign-out path when callback state is a sign-in state', async () => {
    mockWindow.setPathname('/signout').assert();

    const state: CallbackState = {
      mode: 'redirect',
      state: 'state',
      scopes: 'openid',
    };

    mockStorage.setCallbackState(state);

    const instance = testInstance({ storage: mockStorage });

    await expect(instance.processCallback()).resolves.toBeUndefined();

    mockStorage.expectCallbackStateRemoved().expectNoSession();
  });
});
