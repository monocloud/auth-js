// eslint-disable-next-line import/no-extraneous-dependencies
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { fetchBuilder } from '@monocloud/auth-test-utils';
import { now } from '@monocloud/auth-core/internal';
import type { MonoCloudSession } from '@monocloud/auth-core';
import { MonoCloudValidationError } from '@monocloud/auth-core';
import { setSession, testInstance, VanillaJsMockStorage } from './utils';

describe('getTokens() Tests', () => {
  let storage: VanillaJsMockStorage;

  beforeEach(() => {
    storage = new VanillaJsMockStorage();

    if (!(globalThis as any).LockManager) {
      (globalThis as any).LockManager = class LockManager {};
    }

    (globalThis as any).navigator = (globalThis as any).navigator ?? {};
  });

  afterEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it('should throw if session does not exist', async () => {
    const instance = testInstance({ storage });

    const p = instance.getTokens();

    await expect(p).rejects.toBeInstanceOf(MonoCloudValidationError);
    await expect(p).rejects.toThrow('Session does not exist');
  });

  it('should return existing token without refresh when it is not expired', async () => {
    const session: MonoCloudSession = {
      idToken: 'idToken',
      refreshToken: 'rt',
      authorizedScopes: 'openid offline_access',
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid offline_access',
        },
      ],
    };

    setSession(storage, session);

    const instance = testInstance({ storage });

    const tokens = await instance.getTokens();

    expect(tokens).toEqual(
      expect.objectContaining({
        accessToken: 'at',
        accessTokenExpiration: expect.any(Number),
        scopes: 'openid offline_access',
        requestedScopes: 'openid offline_access',
        idToken: 'idToken',
        refreshToken: 'rt',
        isExpired: false,
      })
    );
  });

  it('should refresh when token is expired', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt',
        accessToken: 'newAt',
        refreshToken: 'newRt',
        scope: 'openid offline_access',
        skipIdToken: true,
      })
      .createSpy();

    const session: MonoCloudSession = {
      idToken: 'oldId',
      refreshToken: 'rt',
      authorizedScopes: 'openid offline_access',
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 10,
          scopes: 'openid offline_access',
          requestedScopes: 'openid offline_access',
        },
      ],
    };

    setSession(storage, session);

    const instance = testInstance({ storage });

    const tokens = await instance.getTokens();

    expect(tokens).toEqual(
      expect.objectContaining({
        accessToken: 'newAt',
        refreshToken: 'newRt',
        idToken: 'oldId',
        isExpired: false,
      })
    );

    fetchSpy.assert();
  });

  it('should refresh when forceRefresh is true even if token is not expired', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt',
        accessToken: 'newAt',
        refreshToken: 'newRt',
        scope: 'openid offline_access',
        skipIdToken: true,
      })
      .createSpy();

    const session: MonoCloudSession = {
      idToken: 'oldId',
      refreshToken: 'rt',
      authorizedScopes: 'openid offline_access',
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid offline_access',
        },
      ],
    };

    setSession(storage, session);

    const instance = testInstance({ storage });

    const tokens = await instance.getTokens({ forceRefresh: true });

    expect(tokens.accessToken).toBe('newAt');
    expect(tokens.refreshToken).toBe('newRt');

    fetchSpy.assert();
  });

  it('should resolve scopes from options.resources when resource is provided without scopes, then refresh using those scopes', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt&scope=api.read&resource=api',
        accessToken: 'newAt',
        refreshToken: 'newRt',
        scope: 'api.read',
        skipIdToken: true,
      })
      .createSpy();

    const session: MonoCloudSession = {
      idToken: 'oldId',
      refreshToken: 'rt',
      authorizedScopes: 'openid offline_access',
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid offline_access',
        },
      ],
    };

    setSession(storage, session);

    const instance = testInstance({
      storage,
      resources: [{ resource: 'api', scopes: 'api.read' }],
    });

    const tokens = await instance.getTokens({ resource: 'api' });

    expect(tokens).toEqual(
      expect.objectContaining({
        accessToken: 'newAt',
        refreshToken: 'newRt',
        requestedScopes: 'api.read',
        scopes: 'api.read',
      })
    );

    fetchSpy.assert();
  });

  it('should not infer scopes if a no-scope resource entry exists (resource match with scopes undefined)', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt&resource=api',
        accessToken: 'newAt',
        refreshToken: 'newRt',
        scope: 'openid',
        skipIdToken: true,
      })
      .createSpy();

    const session: MonoCloudSession = {
      idToken: 'oldId',
      refreshToken: 'rt',
      authorizedScopes: 'openid offline_access',
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid offline_access',
        },
      ],
    };

    setSession(storage, session);

    const instance = testInstance({
      storage,
      resources: [{ resource: 'api' }, { resource: 'api', scopes: 'api.read' }],
    });

    const tokens = await instance.getTokens({
      resource: 'api',
      forceRefresh: true,
    });

    expect(tokens.accessToken).toBe('newAt');
    fetchSpy.assert();
  });
});
