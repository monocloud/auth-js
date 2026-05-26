// eslint-disable-next-line import/no-extraneous-dependencies
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  fetchBuilder,
  generateIdToken,
  MockWindow,
} from '@monocloud/auth-test-utils';
import {
  ensureLockManagerStub,
  setSession,
  testInstance,
  VanillaJsMockStorage,
} from './utils';
import {
  MonoCloudHttpError,
  MonoCloudSession,
  MonoCloudValidationError,
} from '@monocloud/auth-core';
import { now } from '@monocloud/auth-core/internal';

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

  beforeEach(() => {
    mockWindow = new MockWindow();
    mockStorage = new VanillaJsMockStorage();
    ensureLockManagerStub();
  });

  afterEach(() => {
    mockWindow.restore();
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it('should throw if no session exists', async () => {
    const instance = testInstance({ storage: mockStorage });

    const error = await instance.refreshSession().catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudValidationError);
    expect(error.message).toBe(
      'Ensure the user is authenticated before refreshing the session'
    );
  });

  it('should scope the lock key by sessionKey when set', async () => {
    // @ts-expect-error set custom key
    window.sessionKey = 'custom';

    const instance = testInstance({
      storage: mockStorage,
      sessionKey: 'custom',
    });

    const error = await instance.refreshSession().catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudValidationError);
    expect(error.message).toBe(
      'Ensure the user is authenticated before refreshing the session'
    );

    // @ts-expect-error set to undefined
    delete window.sessionKey;
  });

  it('should throw an error if there is no refresh token', async () => {
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

    const error = await instance.refreshSession().catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudValidationError);
    expect(error.message).toBe(
      'Refresh token not found. Sign in with offline_access scope to get the refresh token.'
    );
  });

  it('should refresh successfully', async () => {
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

    await instance.refreshSession();

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

  it('should forward refreshGrantOptions to the underlying client', async () => {
    const idToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureRefreshToken({
        idToken,
        accessToken: 'newAt',
        refreshToken: 'newRt',
        body: 'grant_type=refresh_token&refresh_token=rt&scope=orders%3Awrite&resource=api%3A%2F%2Forders',
      })
      .configureUserinfo({ accessToken: 'newAt' })
      .createSpy();

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'openid',
          requestedScopes: 'openid',
          accessTokenExpiration: now() + 1000,
        },
      ],
      refreshToken: 'rt',
      authorizedScopes: 'openid',
    };

    setSession(mockStorage, session);

    const instance = testInstance({ storage: mockStorage });

    await instance.refreshSession({
      refreshGrantOptions: {
        resource: 'api://orders',
        scopes: 'orders:write',
      },
    });

    fetchSpy.assert();
  });

  it('should throw an error when refreshing session fails', async () => {
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

    const error = await instance.refreshSession().catch(e => e);

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
});
