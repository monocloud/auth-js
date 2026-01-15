// eslint-disable-next-line import/no-extraneous-dependencies
import { beforeEach, describe, expect, it, vi } from 'vitest';
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

    try {
      await instance.refetchUserInfo();
      throw new Error();
    } catch (e) {
      expect(e).toBeInstanceOf(MonoCloudValidationError);
      expect((e as any).message).toBe(
        'Ensure the user is authenticated before refetching userinfo'
      );
    }
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

    try {
      await instance.refetchUserInfo();
      throw new Error();
    } catch (e) {
      expect(e).toBeInstanceOf(MonoCloudValidationError);
      expect((e as any).message).toBe(
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
    }
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

    instance.refetchUserInfo().then();

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

    await vi.waitFor(async () => {
      fetchSpy.assert();
      storage.expectSession(sessionNew);
      expect(await instance.getSession()).toEqual(sessionNew);
    });
  });
});
