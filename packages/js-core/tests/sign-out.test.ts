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

    openerSpy1.mockClear();
    openerSpy2.mockClear();
    openerSpy3.mockClear();
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

    await vi.waitFor(async () => {
      expect(await instance.getSession()).toBeUndefined();
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

    await vi.waitFor(async () => {
      expect(await instance.getSession()).toBeUndefined();
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

  // it.each(['Silent', 'Popup'])(
  //   '%s Mode - should process signout callback',
  //   async mode => {
  //     mockWindow
  //       .mockPostMessage()
  //       .setSearch('?state=state')
  //       .setPathname('/signout')
  //       .assert();

  //     const state: CallbackState = {
  //       mode: mode.toLowerCase() as SignOutMode,
  //       signOut: true,
  //       state: 'state',
  //     };

  //     storage.setCallbackState(state);

  //     const instance = testInstance({ storage });

  //     instance.processCallback().then();

  //     await vi.waitFor(() => {
  //       expect(mockWindow.mockedPostMessage).toBeCalledWith(
  //         {
  //           success: true,
  //           source: 'monocloud-javascript-sdk',
  //         },
  //         'http://localhost:3000'
  //       );
  //       storage.expectCallbackStateRemoved();
  //     });
  //   }
  // );

  // it.each(['Silent', 'Popup'])(
  //   '%s Mode - should set an error if states mismatch',
  //   async mode => {
  //     mockWindow
  //       .mockPostMessage()
  //       .setSearch('?state=state')
  //       .setPathname('/signout')
  //       .assert();

  //     const state: CallbackState = {
  //       mode: mode.toLowerCase() as SignOutMode,
  //       signOut: true,
  //       state: 'states',
  //     };

  //     storage.setCallbackState(state);

  //     const instance = testInstance({ storage });

  //     instance.processCallback().then();

  //     await vi.waitFor(() => {
  //       expect(mockWindow.mockedPostMessage).toBeCalledWith(
  //         {
  //           success: false,
  //           source: 'monocloud-javascript-sdk',
  //           serializedError: {
  //             error: 'Sign out states mismatch',
  //             errorType: 'MonoCloudValidationError',
  //           },
  //         },
  //         'http://localhost:3000'
  //       );
  //       storage.expectCallbackStateRemoved();
  //       expect(await instance.getSession()).toBeUndefined();
  //     });
  //   }
  // );

  // it('Popup Mode - should redirect popup to sign out page and resolve when a success message is received', async () => {
  //   const fetchSpy = fetchBuilder()
  //     .configureMetadata()
  //     .configureRevokeToken({ accessToken: true, tokenTypeHint: true })
  //     .createSpy();

  //   mockWindow.assert();

  //   const mockPopup = {
  //     close: vi.fn(),
  //   } as unknown as Window;

  //   const popupSpy = vi.spyOn(window, 'open').mockReturnValue(mockPopup);

  //   const session: MonoCloudSession = {
  //     user: { sub: 'sub' },
  //     accessToken: 'at',
  //     accessTokenExpiration: now() + 1000,
  //   };

  //   setSession(storage, session);

  //   const instance = testInstance({ storage });

  //   expect(await instance.getSession()).toBeDefined();

  //   instance.signOut({ mode: 'popup', revokeTokens: true }).then();

  //   await vi.waitFor(() => {
  //     storage
  //       .expectNoSession()
  //       .expectCallbackState()
  //       .expectCallbackStateMode('popup')
  //       .expectCallbackStateSignOut(true)
  //       .expectCallbackStateState();

  //     expect(await instance.getSession()).toBeUndefined();

  //     expect(window.open).toBeCalledWith(
  //       expect.stringContaining('https://example.com/connect/endsession'),
  //       expect.any(String),
  //       expect.any(String)
  //     );
  //   });

  //   window.dispatchEvent(
  //     new MessageEvent('message', {
  //       data: {
  //         success: true,
  //         source: 'monocloud-javascript-sdk',
  //       },
  //       source: mockPopup,
  //       origin: 'http://localhost:3000',
  //     })
  //   );

  //   await vi.waitFor(() => {
  //     fetchSpy.assert();
  //     expect(mockPopup.close).toBeCalled();
  //     storage.expectNoSession().expectCallbackStateRemoved();
  //     expect(await instance.getSession()).toBeUndefined();
  //   });

  //   popupSpy.mockClear();
  // });

  // it('Popup Mode - should redirect popup to sign out page and reject when an error message is received', async () => {
  //   const fetchSpy = fetchBuilder()
  //     .configureMetadata()
  //     .configureRevokeToken({ accessToken: true, tokenTypeHint: true })
  //     .createSpy();

  //   mockWindow.assert();

  //   const mockPopup = {
  //     close: vi.fn(),
  //   } as unknown as Window;

  //   const popupSpy = vi.spyOn(window, 'open').mockReturnValue(mockPopup);

  //   const session: MonoCloudSession = {
  //     user: { sub: 'sub' },
  //     accessToken: 'at',
  //     accessTokenExpiration: now() + 1000,
  //   };

  //   setSession(storage, session);

  //   const instance = testInstance({ storage });

  //   expect(await instance.getSession()).toBeDefined();

  //   const error = new MonoCloudOPError('some_error', 'something went wrong');

  //   let thrown = false;

  //   instance
  //     .signOut({ mode: 'popup', revokeTokens: true })
  //     .then()
  //     .catch(e => {
  //       expect(e).toBeInstanceOf(MonoCloudOPError);
  //       expect(e?.error).toBe(error.error);
  //       expect(e?.errorDescription).toBe(error.errorDescription);
  //       thrown = true;
  //     });

  //   await vi.waitFor(() => {
  //     storage
  //       .expectNoSession()
  //       .expectCallbackState()
  //       .expectCallbackStateMode('popup')
  //       .expectCallbackStateSignOut(true)
  //       .expectCallbackStateState();

  //     expect(await instance.getSession()).toBeUndefined();

  //     expect(window.open).toBeCalledWith(
  //       expect.stringContaining('https://example.com/connect/endsession'),
  //       expect.any(String),
  //       expect.any(String)
  //     );
  //   });

  //   window.dispatchEvent(
  //     new MessageEvent('message', {
  //       data: {
  //         success: false,
  //         source: 'monocloud-javascript-sdk',
  //         serializedError: serializeError(error),
  //       },
  //       source: mockPopup,
  //       origin: 'http://localhost:3000',
  //     })
  //   );

  //   await vi.waitFor(() => {
  //     fetchSpy.assert();
  //     expect(mockPopup.close).toBeCalled();
  //     expect(thrown).toBe(true);
  //     storage.expectNoSession().expectCallbackStateRemoved();
  //     expect(await instance.getSession()).toBeUndefined();
  //   });

  //   popupSpy.mockClear();
  // });

  // it('Popup Mode - can timeout', async () => {
  //   const fetchSpy = fetchBuilder()
  //     .configureMetadata()
  //     .configureRevokeToken({ accessToken: true, tokenTypeHint: true })
  //     .createSpy();

  //   mockWindow.assert();

  //   const mockPopup = {
  //     close: vi.fn(),
  //   } as unknown as Window;

  //   const popupSpy = vi.spyOn(window, 'open').mockReturnValue(mockPopup);

  //   const session: MonoCloudSession = {
  //     user: { sub: 'sub' },
  //     accessToken: 'at',
  //     accessTokenExpiration: now() + 1000,
  //   };

  //   setSession(storage, session);

  //   const instance = testInstance({ storage, authWindowTimeout: 0.1 });

  //   expect(await instance.getSession()).toBeDefined();

  //   let thrown = false;

  //   instance
  //     .signOut({ mode: 'popup', revokeTokens: true })
  //     .then()
  //     .catch(e => {
  //       expect(e).toBeInstanceOf(MonoCloudJsError);
  //       expect(e?.message).toBe('Sign out window timed out');
  //       thrown = true;
  //     });

  //   await vi.waitFor(() => {
  //     storage
  //       .expectNoSession()
  //       .expectCallbackState()
  //       .expectCallbackStateMode('popup')
  //       .expectCallbackStateSignOut(true)
  //       .expectCallbackStateState();

  //     expect(await instance.getSession()).toBeUndefined();

  //     expect(window.open).toBeCalledWith(
  //       expect.stringContaining('https://example.com/connect/endsession'),
  //       expect.any(String),
  //       expect.any(String)
  //     );
  //   });

  //   await vi.waitFor(() => {
  //     fetchSpy.assert();
  //     expect(mockPopup.close).toBeCalled();
  //     expect(thrown).toBe(true);
  //     storage.expectNoSession().expectCallbackStateRemoved();
  //     expect(await instance.getSession()).toBeUndefined();
  //   });

  //   popupSpy.mockClear();
  // });

  // it('Popup Mode - should throw error if popup fails to open', async () => {
  //   const fetchSpy = fetchBuilder()
  //     .configureMetadata()
  //     .configureRevokeToken({ accessToken: true, tokenTypeHint: true })
  //     .createSpy();

  //   const popupSpy = vi.spyOn(window, 'open').mockReturnValue(null);

  //   const session: MonoCloudSession = {
  //     user: { sub: 'sub' },
  //     accessToken: 'at',
  //     accessTokenExpiration: now() + 1000,
  //   };

  //   setSession(storage, session);

  //   const instance = testInstance({ storage });

  //   expect(await instance.getSession()).toBeDefined();

  //   let thrown = false;

  //   instance
  //     .signOut({ mode: 'popup', revokeTokens: true })
  //     .then()
  //     .catch(e => {
  //       expect(e).toBeInstanceOf(MonoCloudJsError);
  //       expect(e?.message).toBe('Could not open popup');
  //       thrown = true;
  //     });

  //   await vi.waitFor(() => {
  //     storage.expectCallbackStateRemoved();
  //     expect(await instance.getSession()).toBeUndefined();
  //     fetchSpy.assert();
  //     expect(thrown).toBe(true);
  //   });

  //   popupSpy.mockClear();
  // });

  // it('Popup Mode - throws when user closes the window', async () => {
  //   const fetchSpy = fetchBuilder().configureMetadata().createSpy();

  //   const popup = window.open();

  //   const popupSpy = vi.spyOn(window, 'open').mockReturnValue(popup);

  //   const instance = testInstance({ storage });

  //   let thrown = false;

  //   instance
  //     .signOut({ mode: 'popup', revokeTokens: true })
  //     .then()
  //     .catch(e => {
  //       expect(e).toBeInstanceOf(MonoCloudJsError);
  //       expect(e?.message).toBe('Sign out window closed by user');
  //       thrown = true;
  //     });

  //   popup?.close();

  //   await vi.waitFor(() => {
  //     storage.expectCallbackStateRemoved();
  //     expect(await instance.getSession()).toBeUndefined();
  //     expect(thrown).toBe(true);
  //     fetchSpy.assert();
  //   });

  //   popupSpy.mockClear();
  // });

  // it('should only resolve the promise if the origin is appUrl', async () => {
  //   const fetchSpy = fetchBuilder()
  //     .configureMetadata()
  //     .configureRevokeToken({ accessToken: true, tokenTypeHint: true })
  //     .createSpy();

  //   mockWindow.assert();

  //   const mockPopup = {
  //     close: vi.fn(),
  //   } as unknown as Window;

  //   const popupSpy = vi.spyOn(window, 'open').mockReturnValue(mockPopup);

  //   const session: MonoCloudSession = {
  //     user: { sub: 'sub' },
  //     accessToken: 'at',
  //     accessTokenExpiration: now() + 1000,
  //   };

  //   setSession(storage, session);

  //   const instance = testInstance({ storage });

  //   expect(await instance.getSession()).toBeDefined();

  //   instance.signOut({ mode: 'popup', revokeTokens: true }).then();

  //   await vi.waitFor(() => {
  //     expect(window.open).toBeCalled();
  //   });

  //   window.dispatchEvent(
  //     new MessageEvent('message', {
  //       data: {
  //         success: true,
  //         source: 'monocloud-javascript-sdk',
  //       },
  //       source: mockPopup,
  //       origin: 'http://hackersite.com',
  //     })
  //   );

  //   expect(mockPopup.close).not.toBeCalled();

  //   window.dispatchEvent(
  //     new MessageEvent('message', {
  //       data: {
  //         success: true,
  //         source: 'monocloud-javascript-sdk',
  //       },
  //       source: mockPopup,
  //       origin: 'http://localhost:3000',
  //     })
  //   );

  //   await vi.waitFor(() => {
  //     fetchSpy.assert();
  //     expect(mockPopup.close).toBeCalled();
  //     expect(await instance.getSession()).toBeUndefined();
  //   });

  //   popupSpy.mockClear();
  // });

  // it('should only resolve the promise if the source is parent window', async () => {
  //   const fetchSpy = fetchBuilder()
  //     .configureMetadata()
  //     .configureRevokeToken({ accessToken: true, tokenTypeHint: true })
  //     .createSpy();

  //   mockWindow.assert();

  //   const mockPopup = {
  //     close: vi.fn(),
  //   } as unknown as Window;

  //   const popupSpy = vi.spyOn(window, 'open').mockReturnValue(mockPopup);

  //   const session: MonoCloudSession = {
  //     user: { sub: 'sub' },
  //     accessToken: 'at',
  //     accessTokenExpiration: now() + 1000,
  //   };

  //   setSession(storage, session);

  //   const instance = testInstance({ storage });

  //   expect(await instance.getSession()).toBeDefined();

  //   instance.signOut({ mode: 'popup', revokeTokens: true }).then();

  //   await vi.waitFor(() => {
  //     expect(window.open).toBeCalled();
  //   });

  //   window.dispatchEvent(
  //     new MessageEvent('message', {
  //       data: {
  //         success: true,
  //         source: 'monocloud-javascript-sdk',
  //       },
  //       source: {} as unknown as Window,
  //       origin: 'http://localhost:3000',
  //     })
  //   );

  //   expect(mockPopup.close).not.toBeCalled();

  //   window.dispatchEvent(
  //     new MessageEvent('message', {
  //       data: {
  //         success: true,
  //         source: 'monocloud-javascript-sdk',
  //       },
  //       source: mockPopup,
  //       origin: 'http://localhost:3000',
  //     })
  //   );

  //   await vi.waitFor(() => {
  //     fetchSpy.assert();
  //     expect(mockPopup.close).toBeCalled();
  //     expect(await instance.getSession()).toBeUndefined();
  //   });

  //   popupSpy.mockClear();
  // });

  // it('should only resolve the promise if data.source is monocloud-javascript-sdk', async () => {
  //   const fetchSpy = fetchBuilder()
  //     .configureMetadata()
  //     .configureRevokeToken({ accessToken: true, tokenTypeHint: true })
  //     .createSpy();

  //   mockWindow.assert();

  //   const mockPopup = {
  //     close: vi.fn(),
  //   } as unknown as Window;

  //   const popupSpy = vi.spyOn(window, 'open').mockReturnValue(mockPopup);

  //   const session: MonoCloudSession = {
  //     user: { sub: 'sub' },
  //     accessToken: 'at',
  //     accessTokenExpiration: now() + 1000,
  //   };

  //   setSession(storage, session);

  //   const instance = testInstance({ storage });

  //   expect(await instance.getSession()).toBeDefined();

  //   instance.signOut({ mode: 'popup', revokeTokens: true }).then();

  //   await vi.waitFor(() => {
  //     expect(window.open).toBeCalled();
  //   });

  //   window.dispatchEvent(
  //     new MessageEvent('message', {
  //       data: {
  //         success: true,
  //         source: 'someoneelse',
  //       },
  //       source: mockPopup,
  //       origin: 'http://localhost:3000',
  //     })
  //   );

  //   expect(mockPopup.close).not.toBeCalled();

  //   window.dispatchEvent(
  //     new MessageEvent('message', {
  //       data: {
  //         success: true,
  //         source: 'monocloud-javascript-sdk',
  //       },
  //       source: mockPopup,
  //       origin: 'http://localhost:3000',
  //     })
  //   );

  //   await vi.waitFor(() => {
  //     fetchSpy.assert();
  //     expect(mockPopup.close).toBeCalled();
  //     expect(await instance.getSession()).toBeUndefined();
  //   });

  //   popupSpy.mockClear();
  // });
});
