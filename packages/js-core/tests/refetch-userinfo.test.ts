// eslint-disable-next-line import/no-extraneous-dependencies
import { beforeEach, describe, expect, it } from 'vitest';
import type { MonoCloudSession } from '@monocloud/auth-core';
import { now } from '@monocloud/auth-core/internal';
import { fetchBuilder } from '@monocloud/auth-test-utils';
import { setSession, testInstance, VanillaJsMockStorage } from './utils';
import { MonoCloudValidationError } from '@monocloud/auth-core';

describe('refetchUserinfo() Tests', () => {
  let storage: VanillaJsMockStorage;

  beforeEach(() => {
    storage = new VanillaJsMockStorage();
    window.localStorage.clear();
  });

  it('should throw an error if there is no session', async () => {
    const instance = testInstance({ storage });

    const p = instance.refetchUserInfo();

    await expect(p).rejects.toBeInstanceOf(MonoCloudValidationError);
    await expect(p).rejects.toThrow(
      'Ensure the user is authenticated before refetching userinfo'
    );
  });

  it('should throw an error if there userinfo fetch fails', async () => {
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
      refreshToken: 'rt',
    };

    await setSession(storage, session);

    const instance = testInstance({ storage });

    expect(await instance.getSession()).toBeDefined();

    const p = instance.refetchUserInfo();

    await expect(p).rejects.toBeInstanceOf(MonoCloudValidationError);
    await expect(p).rejects.toThrow(
      'Fetching userinfo requires the openid scope'
    );

    expect(await instance.getSession()).toEqual({
      user: { sub: 'sub' },
      refreshToken: 'rt',
      authorizedScopes: 'token',
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'token',
          requestedScopes: 'token',
          accessTokenExpiration: expect.any(Number),
        },
      ],
    });
  });

  it('should refetch userinfo successfully', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureUserinfo({
        claims: { new: 'claim', from: 'userinfo', username: 'username' },
      })
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
      authorizedScopes: 'openid',
      refreshToken: 'rt',
    };

    await setSession(storage, session);

    const instance = testInstance({ storage });

    expect(await instance.getSession()).toEqual({
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'openid',
          requestedScopes: 'openid',
          accessTokenExpiration: expect.any(Number),
        },
      ],
      authorizedScopes: 'openid',
      refreshToken: 'rt',
    });

    await instance.refetchUserInfo();

    const sessionNew: MonoCloudSession = {
      user: {
        sub: 'sub',
        new: 'claim',
        from: 'userinfo',
        username: 'username',
      },
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'openid',
          requestedScopes: 'openid',
          accessTokenExpiration: expect.any(Number),
        },
      ],
      refreshToken: 'rt',
      authorizedScopes: 'openid',
    };

    fetchSpy.assert();
    storage.expectSession(sessionNew);
    expect(await instance.getSession()).toEqual(sessionNew);
  });

  it('should throw an error if default token is not present', async () => {
    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      authorizedScopes: 'openid',
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'profile',
          requestedScopes: 'profile',
          accessTokenExpiration: now() + 1000,
          resource: 'some-api',
        },
      ],
    };

    await setSession(storage, session);

    const instance = testInstance({ storage });

    const p = instance.refetchUserInfo();

    await expect(p).rejects.toBeInstanceOf(MonoCloudValidationError);
    await expect(p).rejects.toThrow('Default token not found');
  });
});
