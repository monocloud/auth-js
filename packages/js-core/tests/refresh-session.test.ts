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

vi.mock('browser-tabs-lock', () => {
  return {
    default: class TabLockMock {
      acquireLock = vi.fn(() => true);

      releaseLock = vi.fn(() => void 0);
    },
  };
});

describe('instance.refreshSession() Tests', () => {
  let mockWindow: MockWindow;
  let storage: VanillaJsMockStorage;

  const urlRegex =
    /^https:\/\/example\.com\/connect\/authorize\?client_id=clientId&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=[a-zA-Z0-9+_% -]+&response_type=[a-zA-Z0-9_+]+&nonce=[a-zA-Z0-9_-]+&prompt=[a-zA-Z0-9_-]+&code_challenge=[a-zA-Z0-9_-]+&code_challenge_method=S256&state=[a-zA-Z0-9_-]+$/;

  beforeEach(() => {
    mockWindow = new MockWindow();
    storage = new VanillaJsMockStorage();

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
    const instance = testInstance({ storage });

    const p = instance.refreshSession({ mode: 'refresh_token' });

    await expect(p).rejects.toBeInstanceOf(MonoCloudValidationError);
    await expect(p).rejects.toThrow(
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

    setSession(storage, session);

    const instance = testInstance({ storage });

    expect(await instance.getSession()).toBeDefined();

    const p = instance.refreshSession({
      mode: 'refresh_token',
    });

    await expect(p).rejects.toBeInstanceOf(MonoCloudValidationError);
    await expect(p).rejects.toThrow(
      'Refresh token not found. Sign in with offline_access scope to get the refresh token.'
    );
  });

  it('should throw error if the code is not running in the main window', async () => {
    vi.spyOn(window, 'opener', 'get').mockReturnValue(null);
    vi.spyOn(window, 'parent', 'get').mockReturnValue({} as unknown as Window);
    vi.spyOn(window, 'top', 'get').mockReturnValue({} as unknown as Window);

    const instance = testInstance({ storage });

    const p = instance.refreshSession();

    await expect(p).rejects.toBeInstanceOf(MonoCloudJsError);
    await expect(p).rejects.toThrow(
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

    setSession(storage, session);

    const instance = testInstance({ storage });

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
      storage.expectSession(sessionNew).expectCallbackStateRemoved();
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

    setSession(storage, storedSession);

    const instance = testInstance({ storage });

    const p = instance.refreshSession({ mode: 'refresh_token' });

    await expect(p).rejects.toBeInstanceOf(MonoCloudHttpError);
    await expect(p).rejects.toThrow(
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

      setSession(storage, existingSession);

      const instance = testInstance({
        storage,
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

        storage.expectCallbackStateRemoved();
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

    setSession(storage, existingSession);

    const instance = testInstance({ storage });

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

    await expect(refreshPromise).rejects.toBeInstanceOf(MonoCloudOPError);
    await expect(refreshPromise).rejects.toMatchObject({
      error: 'some_error',
      errorDescription: 'something went wrong',
    });

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();
      storage.expectCallbackStateRemoved();

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

    setSession(storage, existingSession);

    const instance = testInstance({
      storage,
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

    await expect(refreshPromise).rejects.toBeInstanceOf(MonoCloudJsError);
    await expect(refreshPromise).rejects.toThrow('Window timed out');

    await vi.waitFor(async () => {
      expect(mockPopup.close).toHaveBeenCalled();

      storage.expectCallbackStateRemoved();

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

    setSession(storage, existingSession);

    const instance = testInstance({ storage });

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

    const p = instance.refreshSession({ mode: 'popup' });

    await expect(p).rejects.toBeInstanceOf(MonoCloudJsError);
    await expect(p).rejects.toMatchObject({ message: 'Could not open popup' });

    storage.expectCallbackStateRemoved();

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

    setSession(storage, existingSession);

    const instance = testInstance({ storage });

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

    setSession(storage, existingSession);

    const instance = testInstance({ storage });

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

    await expect(refreshPromise).rejects.toBeInstanceOf(MonoCloudOPError);
    await expect(refreshPromise).rejects.toMatchObject({
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

    setSession(storage, existingSession);

    const instance = testInstance({
      storage,
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
    setSession(storage, existingSession);

    const instance = testInstance({ storage });

    const refreshPromise = instance.refreshSession({ mode: 'popup' });

    await vi.waitFor(() => {
      expect(mockPopup.location.href).toMatch(urlRegex);
    });

    mockPopup.closed = true;

    await expect(refreshPromise).rejects.toBeInstanceOf(MonoCloudJsError);
    await expect(refreshPromise).rejects.toThrow('Window closed by user');

    await vi.waitFor(async () => {
      storage.expectCallbackStateRemoved();

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
    setSession(storage, existingSession);

    const instance = testInstance({
      storage,
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
    setSession(storage, existingSession);

    const instance = testInstance({
      storage,
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

    setSession(storage, existingSession);

    const instance = testInstance({
      storage,
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
});
