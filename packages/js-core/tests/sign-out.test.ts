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
  let storage: VanillaJsMockStorage;

  beforeEach(() => {
    mockWindow = new MockWindow();
    storage = new VanillaJsMockStorage();
  });

  afterEach(() => {
    mockWindow.restore();
    window.localStorage.clear();
  });

  it('should set custom redirect uri from options', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow
      .expectQuery(
        'post_logout_redirect_uri',
        'http://localhost:3000/signout/custom'
      )
      .assert();

    const instance = testInstance({ storage });

    instance
      .signOut({
        postLogoutRedirectUri: 'http://localhost:3000/signout/custom',
      })
      .then();

    await vi.waitFor(() => {
      expect(window.location.assign).toHaveBeenCalledOnce();
      fetchSpy.assert();
    });
  });

  it('should throw error if the code is not running in the main window', async () => {
    const openerSpy1 = vi.spyOn(window, 'opener', 'get').mockReturnValue(null);
    const openerSpy2 = vi
      .spyOn(window, 'parent', 'get')
      .mockReturnValue({} as unknown as Window);
    const openerSpy3 = vi
      .spyOn(window, 'top', 'get')
      .mockReturnValue({} as unknown as Window);
    const instance = testInstance({ storage });

    try {
      await instance.signOut();
      throw new Error();
    } catch (e) {
      expect(e).toBeInstanceOf(MonoCloudJsError);
      expect((e as any).message).toBe(
        'Initiating an authentication flow in a popup or iframe is not supported'
      );
    }

    openerSpy1.mockRestore();
    openerSpy2.mockRestore();
    openerSpy3.mockRestore();
  });

  it('should redirect to signout without state, logout uri and idToken', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow
      .expectQuery('client_id', 'clientId')
      .doNotExpectQueryKey('state')
      .doNotExpectQueryKey('post_logout_redirect_uri')
      .doNotExpectQueryKey('id_token_hint')
      .assert();

    const instance = testInstance({
      storage,
      signOutCallbackPath: undefined,
    });

    instance.signOut().then();

    await vi.waitFor(() => {
      expect(window.location.assign).toHaveBeenCalledOnce();
      fetchSpy.assert();
    });
  });

  it('should redirect to signout without state, logout uri and idToken (Session Present)', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow
      .expectQuery('client_id', 'clientId')
      .doNotExpectQueryKey('state')
      .doNotExpectQueryKey('post_logout_redirect_uri')
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

    await setSession(storage, session);

    const instance = testInstance({
      storage,
      signOutCallbackPath: undefined,
    });

    expect(await instance.getSession()).toBeDefined();

    instance.signOut().then();

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

    const instance = testInstance({ storage });

    instance.signOut().then();

    await vi.waitFor(() => {
      expect(window.location.assign).toHaveBeenCalledWith(
        expect.stringContaining('https://example.com/connect/endsession')
      );
      storage
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

    storage.setCallbackState(state);

    const instance = testInstance({ storage, signOutCallbackPath: '/signout' });

    instance.processCallback().then();

    await vi.waitFor(() => {
      storage.expectCallbackStateRemoved();
    });
  });

  it('Redirect Mode - should process signout callback even if the signOutCallbackPath is not set', async () => {
    mockWindow.setSearch('?state=state').setPathname('/').assert();

    const state: CallbackState = {
      mode: 'redirect',
      signOut: true,
      state: 'state',
    };

    storage.setCallbackState(state);

    const instance = testInstance({
      storage,
      signOutCallbackPath: undefined,
    });

    instance.processCallback().then();

    await vi.waitFor(() => {
      storage.expectCallbackStateRemoved();
    });
  });

  it('Redirect Mode - should set an error if states mismatch', async () => {
    mockWindow.setSearch('?state=state').setPathname('/signout').assert();

    const state: CallbackState = {
      mode: 'redirect',
      signOut: true,
      state: 'states',
    };

    storage.setCallbackState(state);

    const instance = testInstance({ storage });

    try {
      await instance.processCallback();
    } catch (e) {
      expect(e).toBeInstanceOf(MonoCloudValidationError);
      expect((e as any).message).toBe('Sign out states mismatch');
    }

    await vi.waitFor(() => {
      storage.expectCallbackStateRemoved();
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

    storage.setCallbackState(state);

    const instance = testInstance({
      storage,
      signOutCallbackPath: '/signout',
    });

    instance.processCallback();

    await vi.waitFor(() => {
      expect(mockWindow.parentPostMessage).toHaveBeenCalledWith(
        expect.objectContaining({
          source: 'monocloud-auth-js-core',
          url: 'http://localhost:3000/signout?state=state',
        }),
        'http://localhost:3000'
      );
    });
  });

  it('Popup Mode - should throw error if states mismatch', async () => {
    fetchBuilder().configureMetadata().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    const popupSpy = vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({
      storage,
      signOutCallbackPath: '/signout',
    });

    const signOutPromise = instance.signOut({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toContain(
        'https://example.com/connect/endsession'
      );
    });

    expect(window.open).toBeCalledWith(
      'about:blank',
      'mc.popup',
      expect.any(String)
    );

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: 'http://localhost:3000/signout?state=wrong-state',
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signOutPromise).rejects.toThrow(MonoCloudValidationError);
    await expect(signOutPromise).rejects.toThrow('Sign out states mismatch');

    expect(mockPopup.close).toBeCalled();

    popupSpy.mockClear();
  });

  it('Popup Mode - should redirect popup to sign out page and resolve when a success message is received', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    const popupSpy = vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({ storage, signOutCallbackPath: undefined });

    instance.signOut({ mode: 'popup' }).then();

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toContain(
        'https://example.com/connect/endsession'
      );
    });

    expect(window.open).toBeCalledWith(
      'about:blank',
      'mc.popup',
      expect.any(String)
    );

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000`,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await vi.waitFor(() => {
      fetchSpy.assert();
      expect(mockPopup.close).toBeCalled();
      storage.expectCallbackStateRemoved();
    });

    popupSpy.mockClear();
  });

  it('Popup Mode - can timeout', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    const popupSpy = vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({ storage, authWindowTimeout: 0.1 });

    let thrown = false;

    instance
      .signOut({ mode: 'popup' })
      .then()
      .catch(e => {
        expect(e).toBeInstanceOf(MonoCloudJsError);
        expect(e?.message).toBe('Window timed out');
        thrown = true;
      });

    await vi.waitFor(
      () => {
        expect(thrown).toBe(true);
      },
      { timeout: 1000 }
    );

    expect(mockPopup.close).toBeCalled();

    expect(window.open).toBeCalledWith(
      'about:blank',
      'mc.popup',
      expect.any(String)
    );

    expect(mockPopup.location.href).toContain(
      'https://example.com/connect/endsession'
    );

    fetchSpy.assert();
    popupSpy.mockClear();
  });

  it('Popup Mode - should throw error if popup fails to open', async () => {
    const fetchSpy = fetchBuilder().createSpy();

    const popupSpy = vi.spyOn(window, 'open').mockReturnValue(null);

    const instance = testInstance({ storage });

    let thrown = false;

    instance.signOut({ mode: 'popup' }).catch(e => {
      expect(e).toBeInstanceOf(MonoCloudJsError);
      expect(e?.message).toBe('Could not open popup');
      thrown = true;
    });

    await vi.waitFor(() => {
      fetchSpy.assert();
      expect(thrown).toBe(true);
      storage.expectCallbackStateRemoved();
    });

    popupSpy.mockClear();
  });

  it('Popup Mode - throws when user closes the window', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    };

    const popupSpy = vi
      .spyOn(window, 'open')
      .mockReturnValue(mockPopup as unknown as Window);

    const instance = testInstance({ storage });

    let thrown = false;

    instance
      .signOut({ mode: 'popup' })
      .then()
      .catch(e => {
        expect(e).toBeInstanceOf(MonoCloudJsError);
        expect(e?.message).toBe('Window closed by user');
        thrown = true;
      });

    setTimeout(() => {
      mockPopup.closed = true;
    }, 200);

    await vi.waitFor(() => {
      expect(thrown).toBe(true);
      fetchSpy.assert();
    });

    popupSpy.mockClear();
  });

  it('should only resolve the promise if the origin is appUrl', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    const popupSpy = vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const instance = testInstance({
      storage,
      signOutCallbackPath: undefined,
    });

    instance.signOut({ mode: 'popup' }).then();

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toContain(
        'https://example.com/connect/endsession'
      );
    });

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000`,
        },
        source: mockPopup,
        origin: 'http://yyy.com',
      })
    );

    expect(mockPopup.close).not.toBeCalled();

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000`,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await vi.waitFor(() => {
      fetchSpy.assert();
      expect(mockPopup.close).toBeCalled();
    });

    popupSpy.mockClear();
  });

  it('should only resolve the promise if the source is the expected popup window', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    };

    const popupSpy = vi
      .spyOn(window, 'open')
      .mockReturnValue(mockPopup as unknown as Window);

    const instance = testInstance({
      storage,
      signOutCallbackPath: undefined,
    });

    expect(await instance.getSession()).toBeUndefined();

    instance.signOut({ mode: 'popup' }).then();

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toContain(
        'https://example.com/connect/endsession'
      );
    });

    const randomWindow = {} as Window;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000`,
        },
        source: randomWindow,
        origin: 'http://localhost:3000',
      })
    );

    expect(mockPopup.close).not.toBeCalled();

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000`,
        },
        source: mockPopup as unknown as Window,
        origin: 'http://localhost:3000',
      })
    );

    await vi.waitFor(() => {
      fetchSpy.assert();
      expect(mockPopup.close).toBeCalled();
    });

    popupSpy.mockClear();
  });

  it('should only resolve the promise if data.source is the expected SDK identifier', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    };

    const popupSpy = vi
      .spyOn(window, 'open')
      .mockReturnValue(mockPopup as unknown as Window);

    const instance = testInstance({
      storage,
      signOutCallbackPath: undefined,
    });

    expect(await instance.getSession()).toBeUndefined();

    instance.signOut({ mode: 'popup' }).then();

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

    expect(mockPopup.close).not.toBeCalled();

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: `http://localhost:3000`,
        },
        source: mockPopup as unknown as Window,
        origin: 'http://localhost:3000',
      })
    );

    await vi.waitFor(() => {
      fetchSpy.assert();
      expect(mockPopup.close).toBeCalled();
    });

    popupSpy.mockClear();
  });

  it('should only clear local session and return if federatedSignOut is false', async () => {
    fetchBuilder().createSpy();
    const assignSpy = vi.spyOn(window.location, 'assign');
    const openSpy = vi.spyOn(window, 'open');

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

    await setSession(storage, session);

    const instance = testInstance({
      storage,
      federatedSignOut: false,
    });

    expect(await instance.getSession()).toBeDefined();

    await instance.signOut();

    expect(await instance.getSession()).toBeUndefined();
    storage.expectNoSession();

    expect(assignSpy).not.toHaveBeenCalled();

    expect(openSpy).not.toHaveBeenCalled();

    expect(window.fetch).not.toHaveBeenCalled();

    assignSpy.mockRestore();
    openSpy.mockRestore();
  });

  it('Popup Mode - should clear session immediately even if state validation fails', async () => {
    fetchBuilder().configureMetadata().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    const popupSpy = vi.spyOn(window, 'open').mockReturnValue(mockPopup);

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

    await setSession(storage, session);

    const instance = testInstance({ storage });

    const signOutPromise = instance.signOut({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toContain(
        'https://example.com/connect/endsession'
      );
    });
    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: 'http://localhost:3000/signout?state=wrong-state',
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    await expect(signOutPromise).rejects.toThrow('Sign out states mismatch');
    expect(await instance.getSession()).toBeUndefined();
    storage.expectNoSession();

    expect(mockPopup.close).toBeCalled();
    popupSpy.mockClear();
  });

  it('Redirect Mode - should clear session immediately even if state validation fails', async () => {
    mockWindow.setSearch('?state=wrong-state').setPathname('/signout').assert();

    const state: CallbackState = {
      mode: 'redirect',
      signOut: true,
      state: 'correct-state',
    };

    storage.setCallbackState(state);

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

    setSession(storage, session);

    const instance = testInstance({
      storage,
      signOutCallbackPath: '/signout',
    });

    expect(await instance.getSession()).toBeDefined();

    try {
      await instance.processCallback();
    } catch (e) {
      expect(e).toBeInstanceOf(MonoCloudValidationError);
      expect((e as any).message).toBe('Sign out states mismatch');
    }

    await vi.waitFor(async () => {
      expect(await instance.getSession()).toBeUndefined();
      storage.expectNoSession();
      storage.expectCallbackStateRemoved();
    });
  });
});
