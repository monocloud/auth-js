// eslint-disable-next-line import/no-extraneous-dependencies
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  fetchBuilder,
  generateIdToken,
  MockWindow,
} from '@monocloud/auth-test-utils';
import { setSession, testInstance, VanillaJsMockStorage } from './utils';
import {
  MonoCloudHttpError,
  MonoCloudOPError,
  MonoCloudSession,
  MonoCloudValidationError,
  ResponseTypes,
} from '@monocloud/auth-core';
import { now } from '@monocloud/auth-core/internal';
import { MonoCloudJsError } from '../src';

const tabLockMocks = vi.hoisted(() => ({
  acquireLock: vi.fn(() => true),
  releaseLock: vi.fn(() => void 0),
}));

vi.mock('browser-tabs-lock', () => {
  return {
    default: class TabLockMock {
      acquireLock = tabLockMocks.acquireLock;

      releaseLock = tabLockMocks.releaseLock;
    },
  };
});

describe('instance.refreshSession() Tests', () => {
  let mockWindow: MockWindow;
  let mockStorage: VanillaJsMockStorage;

  const urlRegex =
    /^https:\/\/example\.com\/connect\/authorize\?client_id=clientId&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=[a-zA-Z0-9+_% -]+&response_type=[a-zA-Z0-9_+]+&nonce=[a-zA-Z0-9_-]+&prompt=[a-zA-Z0-9_-]+&code_challenge=[a-zA-Z0-9_-]+&code_challenge_method=S256&state=[a-zA-Z0-9_-]+$/;

  beforeEach(() => {
    mockWindow = new MockWindow();
    mockStorage = new VanillaJsMockStorage();

    if (!(globalThis as any).LockManager) {
      (globalThis as any).LockManager = class LockManager {};
    }

    (globalThis as any).navigator = (globalThis as any).navigator ?? {};
  });

  afterEach(() => {
    mockWindow.restore();
    window.localStorage.clear();
  });

  it('should throw if no session exists', async () => {
    const instance = testInstance({ storage: mockStorage });

    const error = await instance
      .refreshSession({ mode: 'refresh_token' })
      .catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudValidationError);
    expect(error.message).toBe(
      'Ensure the user is authenticated before refreshing the session'
    );
  });

  it('Refresh Token Mode - should throw an error if there is no refresh token', async () => {
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

    setSession(mockStorage, session);

    const instance = testInstance({ storage: mockStorage });

    expect(await instance.getSession()).toBeDefined();

    const error = await instance
      .refreshSession({
        mode: 'refresh_token',
      })
      .catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudValidationError);
    expect(error.message).toBe(
      'Refresh token not found. Sign in with offline_access scope to get the refresh token.'
    );
  });

  it('should throw error if the code is not running in the main window', async () => {
    vi.spyOn(window, 'opener', 'get').mockReturnValue(null);
    vi.spyOn(window, 'parent', 'get').mockReturnValue({} as unknown as Window);
    vi.spyOn(window, 'top', 'get').mockReturnValue({} as unknown as Window);

    const instance = testInstance({ storage: mockStorage });

    const error = await instance.refreshSession().catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudJsError);
    expect(error.message).toBe(
      'Initiating an authentication flow in a popup or iframe is not supported'
    );
  });

  it('Refresh Token Mode - should refresh successfully', async () => {
    const idToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureRefreshToken({
        idToken,
        accessToken: 'newAt',
        refreshToken: 'newRt',
        body: 'grant_type=refresh_token&refresh_token=rt',
      })
      .configureUserinfo({ accessToken: 'newAt' })
      .createSpy();

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
      refreshToken: 'rt',
      authorizedScopes: 'token',
    };

    setSession(mockStorage, session);

    const instance = testInstance({ storage: mockStorage });

    await instance.refreshSession({
      mode: 'refresh_token',
    });

    const sessionNew = {
      user: {
        sub: 'sub',
        sub_jwk: expect.any(Object),
        username: 'username',
      },
      accessTokens: [
        {
          accessToken: 'newAt',
          scopes: 'openid offline_access',
          requestedScopes: 'token',
          accessTokenExpiration: expect.any(Number),
        },
      ],
      refreshToken: 'newRt',
      idToken,
      authorizedScopes: 'token',
    };

    await vi.waitFor(async () => {
      fetchSpy.assert();
      mockStorage.expectSession(sessionNew).expectCallbackStateRemoved();
      expect(await instance.getSession()).toEqual(sessionNew);
    });
  });

  it('Refresh Token Mode - should throw an error when refreshing session fails', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        responseCode: 500,
        body: 'grant_type=refresh_token&refresh_token=rt',
      })
      .createSpy();

    const storedSession: MonoCloudSession = {
      user: { sub: 'sub' },
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid',
        },
      ],
      authorizedScopes: 'openid',
    };

    setSession(mockStorage, storedSession);

    const instance = testInstance({ storage: mockStorage });

    const error = await instance
      .refreshSession({ mode: 'refresh_token' })
      .catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudHttpError);
    expect(error.message).toBe(
      'Error while performing refresh token grant. Unexpected status code: 500'
    );

    fetchSpy.assert();

    expect(await instance.getSession()).toEqual(
      expect.objectContaining({
        user: { sub: 'sub' },
        refreshToken: 'rt',
        accessTokens: [
          expect.objectContaining({
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          }),
        ],
      })
    );
  });

  it.each(['code', 'code id_token'])(
    'Popup Mode - should refresh session through popup and resolve when a session message is received - %s',
    async responseType => {
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

      const existingSession: MonoCloudSession = {
        user: { sub: 'sub' },
        refreshToken: 'rt',
        accessTokens: [
          {
            accessToken: 'at',
            accessTokenExpiration: now() + 1000,
            scopes: 'openid offline_access',
            requestedScopes: 'openid',
          },
        ],
        authorizedScopes: 'openid',
      };

      setSession(mockStorage, existingSession);

      const instance = testInstance({
        storage: mockStorage,
        responseType: responseType as ResponseTypes,
      });

      expect(await instance.getSession()).toEqual(
        expect.objectContaining({
          user: { sub: 'sub' },
          refreshToken: 'rt',
          accessTokens: [
            expect.objectContaining({
              accessToken: 'at',
              accessTokenExpiration: expect.any(Number),
            }),
          ],
        })
      );

      const refreshPromise = instance.refreshSession({ mode: 'popup' });

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
        .configureTokenEndpoint({
          accessToken: 'newAt',
          refreshToken: 'newRt',
          idToken,
        })
        .configureUserinfo({
          accessToken: 'newAt',
          claims: { sub: 'sub', email: 'test@example.com' },
        });

      const callbackUrl =
        responseType === 'code'
          ? `http://localhost:3000/callback?code=auth-code&state=${encodeURIComponent(
              generatedState ?? ''
            )}`
          : `http://localhost:3000/callback#state=${encodeURIComponent(
              generatedState ?? ''
            )}&code=auth-code&id_token=${encodeURIComponent('dummy-id-token')}`;

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

      await expect(refreshPromise).resolves.toBeUndefined();

      await vi.waitFor(async () => {
        expect(mockPopup.close).toHaveBeenCalled();

        const saved = await instance.getSession();
        expect(saved).toEqual(
          expect.objectContaining({
            refreshToken: 'newRt',
            idToken: expect.any(String),
            accessTokens: [
              expect.objectContaining({
                accessToken: 'newAt',
                accessTokenExpiration: expect.any(Number),
              }),
            ],
            user: expect.objectContaining({
              sub: 'sub',
              email: 'test@example.com',
            }),
          })
        );

        mockStorage.expectCallbackStateRemoved();
      });

      fetchSpy.assert();
    }
  );

  it('Popup Mode - should reject when redirect has error', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    } as unknown as Window;

    vi.spyOn(window, 'open').mockReturnValue(mockPopup);

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid',
        },
      ],
      authorizedScopes: 'openid',
    };

    setSession(mockStorage, existingSession);

    const instance = testInstance({ storage: mockStorage });

    expect(await instance.getSession()).toEqual(
      expect.objectContaining({
        user: { sub: 'sub' },
        refreshToken: 'rt',
        accessTokens: [
          expect.objectContaining({
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          }),
        ],
      })
    );

    const refreshPromise = instance.refreshSession({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const authorizeUrl = new URL(mockPopup.location.href);
    const generatedState = authorizeUrl.searchParams.get('state');

    const errorCallbackUrl =
      `http://localhost:3000/callback` +
      `?error=some_error` +
      `&error_description=${encodeURIComponent('something went wrong')}` +
      `&state=${encodeURIComponent(generatedState ?? '')}`;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: errorCallbackUrl,
        },
        source: mockPopup,
        origin: 'http://localhost:3000',
      })
    );

    const error = await refreshPromise.catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudOPError);
    expect(error).toMatchObject({
      error: 'some_error',
      errorDescription: 'something went wrong',
    });

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();
      mockStorage.expectCallbackStateRemoved();

      const saved = await instance.getSession();
      expect(saved).toEqual(
        expect.objectContaining({
          user: { sub: 'sub' },
          refreshToken: 'rt',
          accessTokens: [
            expect.objectContaining({
              accessToken: 'at',
              accessTokenExpiration: expect.any(Number),
            }),
          ],
        })
      );

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

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid',
        },
      ],
      authorizedScopes: 'openid',
    };

    setSession(mockStorage, existingSession);

    const instance = testInstance({
      storage: mockStorage,
      authWindowTimeout: 0.1,
    });

    expect(await instance.getSession()).toEqual(
      expect.objectContaining({
        user: { sub: 'sub' },
        refreshToken: 'rt',
        accessTokens: [
          expect.objectContaining({
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          }),
        ],
      })
    );

    const refreshPromise = instance.refreshSession({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    const error = await refreshPromise.catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudJsError);
    expect(error.message).toBe('Window timed out');

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();

      mockStorage.expectCallbackStateRemoved();

      const saved = await instance.getSession();
      expect(saved).toEqual(
        expect.objectContaining({
          user: { sub: 'sub' },
          refreshToken: 'rt',
          accessTokens: [
            expect.objectContaining({
              accessToken: 'at',
              accessTokenExpiration: expect.any(Number),
            }),
          ],
        })
      );

      fetchSpy.assert();
    });
  });

  it('Popup Mode - should throw an error if popup fails to open', async () => {
    mockWindow.assert();

    vi.spyOn(window, 'open').mockReturnValue(null);

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid',
        },
      ],
      authorizedScopes: 'openid',
    };

    setSession(mockStorage, existingSession);

    const instance = testInstance({ storage: mockStorage });

    expect(await instance.getSession()).toEqual(
      expect.objectContaining({
        user: { sub: 'sub' },
        refreshToken: 'rt',
        accessTokens: [
          expect.objectContaining({
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          }),
        ],
      })
    );

    const error = await instance
      .refreshSession({ mode: 'popup' })
      .catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudJsError);
    expect(error).toMatchObject({ message: 'Could not open popup' });

    mockStorage.expectCallbackStateRemoved();

    expect(await instance.getSession()).toEqual(existingSession);
  });

  it('Silent Mode - should refresh session through iframe and resolve when a session message is received', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .createSpy();

    mockWindow.assert();

    const iframe = window.document.createElement('iframe');

    vi.spyOn(window.document, 'createElement').mockReturnValue(iframe);

    vi.spyOn(iframe, 'contentWindow', 'get').mockReturnValue(
      window as unknown as Window
    );

    const appendChildSpy = vi.spyOn(window.document.body, 'appendChild');

    let iframeSrc = '';

    vi.spyOn(iframe, 'setAttribute').mockImplementation(
      (name: string, value: string) => {
        if (name === 'src') iframeSrc = value;
      }
    );

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid',
        },
      ],
      authorizedScopes: 'openid',
    };

    setSession(mockStorage, existingSession);

    const instance = testInstance({ storage: mockStorage });

    expect(await instance.getSession()).toEqual(
      expect.objectContaining({
        user: { sub: 'sub' },
        refreshToken: 'rt',
        accessTokens: [
          expect.objectContaining({
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          }),
        ],
      })
    );

    const refreshPromise = instance.refreshSession();

    await vi.waitFor(() => {
      expect(appendChildSpy).toHaveBeenCalledWith(iframe);
      expect(iframeSrc).toMatch(urlRegex);
    });

    const authorizeUrl = new URL(iframeSrc);
    const generatedState = authorizeUrl.searchParams.get('state');
    const generatedNonce = authorizeUrl.searchParams.get('nonce');

    const idToken = await generateIdToken({
      nonce: generatedNonce ?? undefined,
      claims: { email: 'test@example.com' },
    });

    fetchSpy
      .configureTokenEndpoint({
        accessToken: 'newAt',
        refreshToken: 'newRt',
        idToken,
      })
      .configureUserinfo({
        accessToken: 'newAt',
        claims: { sub: 'sub', email: 'test@example.com' },
      });

    const callbackUrl = `http://localhost:3000/callback?code=auth-code&state=${encodeURIComponent(
      generatedState ?? ''
    )}`;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: callbackUrl,
        },
        source: window,
        origin: 'http://localhost:3000',
      })
    );

    await expect(refreshPromise).resolves.toBeUndefined();

    await vi.waitFor(async () => {
      expect(document.body.contains(iframe)).toBe(false);

      const saved = await instance.getSession();
      expect(saved).toEqual(
        expect.objectContaining({
          refreshToken: 'newRt',
          idToken: expect.any(String),
          accessTokens: [
            expect.objectContaining({
              accessToken: 'newAt',
              accessTokenExpiration: expect.any(Number),
            }),
          ],
          user: expect.objectContaining({
            sub: 'sub',
            email: 'test@example.com',
          }),
        })
      );

      fetchSpy.assert();
    });
  });

  it('Silent Mode - should reject when an error callback url is received', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const iframe = window.document.createElement('iframe');

    vi.spyOn(window.document, 'createElement').mockReturnValue(iframe);

    vi.spyOn(iframe, 'contentWindow', 'get').mockReturnValue(
      window as unknown as Window
    );

    const appendChildSpy = vi.spyOn(window.document.body, 'appendChild');

    let iframeSrc = '';

    vi.spyOn(iframe, 'setAttribute').mockImplementation(
      (name: string, value: string) => {
        if (name === 'src') iframeSrc = value;
      }
    );

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid',
        },
      ],
      authorizedScopes: 'openid',
    };

    setSession(mockStorage, existingSession);

    const instance = testInstance({ storage: mockStorage });

    const refreshPromise = instance.refreshSession({ mode: 'silent' });

    await vi.waitFor(() => {
      expect(appendChildSpy).toHaveBeenCalledWith(iframe);
      expect(iframeSrc).toMatch(urlRegex);
    });

    const authorizeUrl = new URL(iframeSrc);
    const generatedState = authorizeUrl.searchParams.get('state');

    const errorCallbackUrl =
      `http://localhost:3000/callback` +
      `?error=some_error` +
      `&error_description=${encodeURIComponent('something went wrong')}` +
      `&state=${encodeURIComponent(generatedState ?? '')}`;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: errorCallbackUrl,
        },
        source: window,
        origin: 'http://localhost:3000',
      })
    );

    const error = await refreshPromise.catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudOPError);
    expect(error).toMatchObject({
      error: 'some_error',
      errorDescription: 'something went wrong',
    });

    await vi.waitFor(async () => {
      expect(document.body.contains(iframe)).toBe(false);

      const saved = await instance.getSession();
      expect(saved).toEqual(
        expect.objectContaining({
          user: { sub: 'sub' },
          refreshToken: 'rt',
          accessTokens: [
            expect.objectContaining({
              accessToken: 'at',
              accessTokenExpiration: expect.any(Number),
            }),
          ],
        })
      );

      fetchSpy.assert();
    });
  });

  it('Silent Mode - can timeout', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();

    const iframe = window.document.createElement('iframe');

    vi.spyOn(window.document, 'createElement').mockReturnValue(iframe);

    const appendChildSpy = vi.spyOn(window.document.body, 'appendChild');

    let iframeSrc = '';
    vi.spyOn(iframe, 'setAttribute').mockImplementation(
      (name: string, value: string) => {
        if (name === 'src') iframeSrc = value;
      }
    );

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid',
        },
      ],
      authorizedScopes: 'openid',
    };

    setSession(mockStorage, existingSession);

    const instance = testInstance({
      storage: mockStorage,
      authWindowTimeout: 0.1,
    });

    expect(await instance.getSession()).toEqual(
      expect.objectContaining({
        user: { sub: 'sub' },
        refreshToken: 'rt',
        accessTokens: [
          expect.objectContaining({
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          }),
        ],
      })
    );

    const refreshPromise = instance.refreshSession({ mode: 'silent' });

    await vi.waitFor(() => {
      expect(appendChildSpy).toHaveBeenCalledWith(iframe);
      expect(iframeSrc).toMatch(urlRegex);
    });

    await expect(refreshPromise).rejects.toBeInstanceOf(MonoCloudJsError);
    await expect(refreshPromise).rejects.toThrow('Window timed out');

    await vi.waitFor(async () => {
      expect(document.body.contains(iframe)).toBe(false);

      const saved = await instance.getSession();
      expect(saved).toEqual(
        expect.objectContaining({
          user: { sub: 'sub' },
          refreshToken: 'rt',
          accessTokens: [
            expect.objectContaining({
              accessToken: 'at',
              accessTokenExpiration: expect.any(Number),
            }),
          ],
        })
      );

      fetchSpy.assert();
    });
  });

  it('Popup Mode - throws when user closes the window', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const mockPopup = {
      close: vi.fn(),
      closed: false,
      location: { href: '' },
    };

    vi.spyOn(window, 'open').mockReturnValue(mockPopup as unknown as Window);

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid',
        },
      ],
      authorizedScopes: 'openid',
    };
    setSession(mockStorage, existingSession);

    const instance = testInstance({ storage: mockStorage });

    const refreshPromise = instance.refreshSession({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    mockPopup.closed = true;

    await expect(refreshPromise).rejects.toBeInstanceOf(MonoCloudJsError);
    await expect(refreshPromise).rejects.toThrow('Window closed by user');

    await vi.waitFor(async () => {
      mockStorage.expectCallbackStateRemoved();

      const saved = await instance.getSession();
      expect(saved).toEqual(
        expect.objectContaining({
          user: { sub: 'sub' },
          refreshToken: 'rt',
          accessTokens: [
            expect.objectContaining({
              accessToken: 'at',
              accessTokenExpiration: expect.any(Number),
            }),
          ],
        })
      );

      fetchSpy.assert();
    });
  });

  it('should only resolve the promise if the origin is appUrl', async () => {
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

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid',
        },
      ],
      authorizedScopes: 'openid',
    };
    setSession(mockStorage, existingSession);

    const instance = testInstance({
      storage: mockStorage,
      responseType: 'code',
    });

    expect(await instance.getSession()).toEqual(
      expect.objectContaining({
        user: { sub: 'sub' },
        refreshToken: 'rt',
        accessTokens: [
          expect.objectContaining({
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          }),
        ],
      })
    );

    const refreshPromise = instance.refreshSession({ mode: 'popup' });

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
      .configureTokenEndpoint({
        accessToken: 'newAt',
        refreshToken: 'newRt',
        idToken,
      })
      .configureUserinfo({
        accessToken: 'newAt',
        claims: { sub: 'sub', email: 'test@example.com' },
      });

    const callbackUrl = `http://localhost:3000/callback?code=auth-code&state=${encodeURIComponent(
      generatedState ?? ''
    )}`;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: callbackUrl,
        },
        source: mockPopup,
        origin: 'https://yyy.com',
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

    await expect(refreshPromise).resolves.toBeUndefined();

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();

      const saved = await instance.getSession();
      expect(saved).toEqual(
        expect.objectContaining({
          refreshToken: 'newRt',
          idToken: expect.any(String),
          accessTokens: [
            expect.objectContaining({
              accessToken: 'newAt',
              accessTokenExpiration: expect.any(Number),
            }),
          ],
          user: expect.objectContaining({
            sub: 'sub',
            email: 'test@example.com',
          }),
        })
      );

      fetchSpy.assert();
    });
  });

  it('should only resolve the promise if the source is popup window', async () => {
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

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid',
        },
      ],
      authorizedScopes: 'openid',
    };
    setSession(mockStorage, existingSession);

    const instance = testInstance({
      storage: mockStorage,
      responseType: 'code',
    });

    expect(await instance.getSession()).toEqual(
      expect.objectContaining({
        user: { sub: 'sub' },
        refreshToken: 'rt',
        accessTokens: [
          expect.objectContaining({
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          }),
        ],
      })
    );

    const refreshPromise = instance.refreshSession({ mode: 'popup' });

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
      .configureTokenEndpoint({
        accessToken: 'newAt',
        refreshToken: 'newRt',
        idToken,
      })
      .configureUserinfo({
        accessToken: 'newAt',
        claims: { sub: 'sub', email: 'test@example.com' },
      });

    const callbackUrl = `http://localhost:3000/callback?code=auth-code&state=${encodeURIComponent(
      generatedState ?? ''
    )}`;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-js-core',
          url: callbackUrl,
        },
        source: {} as unknown as Window,
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

    await expect(refreshPromise).resolves.toBeUndefined();

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();

      const saved = await instance.getSession();
      expect(saved).toEqual(
        expect.objectContaining({
          refreshToken: 'newRt',
          idToken: expect.any(String),
          accessTokens: [
            expect.objectContaining({
              accessToken: 'newAt',
              accessTokenExpiration: expect.any(Number),
            }),
          ],
          user: expect.objectContaining({
            sub: 'sub',
            email: 'test@example.com',
          }),
        })
      );

      fetchSpy.assert();
    });
  });

  it('should only resolve the promise if data.source is monocloud-auth-js-core', async () => {
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

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid',
        },
      ],
      authorizedScopes: 'openid',
    };

    setSession(mockStorage, existingSession);

    const instance = testInstance({
      storage: mockStorage,
      responseType: 'code',
    });

    expect(await instance.getSession()).toEqual(
      expect.objectContaining({
        user: { sub: 'sub' },
        refreshToken: 'rt',
        accessTokens: [
          expect.objectContaining({
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          }),
        ],
      })
    );

    const refreshPromise = instance.refreshSession({ mode: 'popup' });

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
      .configureTokenEndpoint({
        accessToken: 'newAt',
        refreshToken: 'newRt',
        idToken,
      })
      .configureUserinfo({
        accessToken: 'newAt',
        claims: { sub: 'sub', email: 'test@example.com' },
      });

    const callbackUrl = `http://localhost:3000/callback?code=auth-code&state=${encodeURIComponent(
      generatedState ?? ''
    )}`;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'yyy',
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

    await expect(refreshPromise).resolves.toBeUndefined();

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();

      const saved = await instance.getSession();
      expect(saved).toEqual(
        expect.objectContaining({
          refreshToken: 'newRt',
          idToken: expect.any(String),
          accessTokens: [
            expect.objectContaining({
              accessToken: 'newAt',
              accessTokenExpiration: expect.any(Number),
            }),
          ],
          user: expect.objectContaining({
            sub: 'sub',
            email: 'test@example.com',
          }),
        })
      );

      fetchSpy.assert();
    });
  });

  it('Silent Mode - should combine multiple resources and scopes from options.resources', async () => {
    fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint()
      .configureUserinfo()
      .createSpy();

    mockWindow.assert();

    const iframe = window.document.createElement('iframe');
    vi.spyOn(window.document, 'createElement').mockReturnValue(iframe);
    vi.spyOn(iframe, 'contentWindow', 'get').mockReturnValue(
      window as unknown as Window
    );

    let iframeSrc = '';
    vi.spyOn(iframe, 'setAttribute').mockImplementation((name, value) => {
      if (name === 'src') iframeSrc = value;
    });

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
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
    setSession(mockStorage, existingSession);

    const instance = testInstance({
      storage: mockStorage,
      resources: [
        { resource: 'api://inventory', scopes: 'inv:read' },
        { resource: 'api://orders', scopes: 'orders:write' },
      ],
    });

    instance.refreshSession({ mode: 'silent' });

    await vi.waitFor(() => {
      expect(iframeSrc).toContain('https://example.com/connect/authorize');
    });

    const url = new URL(iframeSrc);

    const resources = url.searchParams.getAll('resource');
    expect(resources).toHaveLength(2);
    expect(resources).toContain('api://inventory');
    expect(resources).toContain('api://orders');

    const scopes = url.searchParams.get('scope')?.split(' ') ?? [];
    expect(scopes).toContain('inv:read');
    expect(scopes).toContain('orders:write');
  });

  it('Silent Mode - should filter out invalid resources and scopes from options.resources', async () => {
    fetchBuilder().configureMetadata().createSpy();
    mockWindow.assert();

    const iframe = window.document.createElement('iframe');
    vi.spyOn(window.document, 'createElement').mockReturnValue(iframe);
    vi.spyOn(iframe, 'contentWindow', 'get').mockReturnValue(
      window as unknown as Window
    );

    let iframeSrc = '';
    vi.spyOn(iframe, 'setAttribute').mockImplementation((name, value) => {
      if (name === 'src') iframeSrc = value;
    });

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
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
    setSession(mockStorage, existingSession);

    const instance = testInstance({
      storage: mockStorage,
      resources: [
        { resource: 'api://valid', scopes: 'scope:valid' },
        { resource: '', scopes: '' },
        { resource: undefined, scopes: undefined },
        {} as any,
      ],
    });

    instance.refreshSession({ mode: 'silent' });

    await vi.waitFor(() => {
      expect(iframeSrc).toContain('https://example.com/connect/authorize');
    });

    const url = new URL(iframeSrc);

    const resources = url.searchParams.getAll('resource');
    expect(resources).toHaveLength(1);
    expect(resources).toContain('api://valid');
    expect(resources).not.toContain('');
    expect(resources).not.toContain('undefined');

    const scopes = url.searchParams.get('scope')?.split(' ') ?? [];
    expect(scopes).toContain('scope:valid');
    expect(scopes).not.toContain('');
    expect(scopes).not.toContain('undefined');
  });

  it('Silent Mode - should throw error if window is crossOriginIsolated', async () => {
    const instance = testInstance({ storage: mockStorage });

    Object.defineProperty(window, 'crossOriginIsolated', {
      value: true,
      configurable: true,
    });

    const error = await instance
      .refreshSession({ mode: 'silent' })
      .catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudJsError);
    expect(error.message).toBe('Isolated Cross-Origin. Cannot create iframe');

    Object.defineProperty(window, 'crossOriginIsolated', {
      value: false,
      configurable: true,
    });
  });
});
