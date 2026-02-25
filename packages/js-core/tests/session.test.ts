// eslint-disable-next-line import/no-extraneous-dependencies
import { describe, it, expect, afterEach } from 'vitest';
import type { MonoCloudSession } from '@monocloud/auth-core';
import { now } from '@monocloud/auth-core/internal';
import { setSession, testInstance } from './utils';
import { LocalStorage } from '../src';

describe('Session Tests', () => {
  afterEach(() => {
    window.localStorage.clear();
  });

  it('should restore valid existing session', async () => {
    const validSession: MonoCloudSession = {
      idToken: 'idToken',
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'openid offline_access',
          requestedScopes: 'openid offline_access',
          accessTokenExpiration: now() + 1000,
        },
      ],
      authorizedScopes: 'openid offline_access',
      refreshToken: 'rt',
      user: { sub: 'sub' },
    };

    await setSession(new LocalStorage(), validSession);

    const instance = testInstance();

    expect(await instance.getSession()).toEqual(validSession);
  });

  it('should restore valid existing session (custom key)', async () => {
    const validSession: MonoCloudSession = {
      idToken: 'idToken',
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'openid offline_access',
          requestedScopes: 'openid offline_access',
          accessTokenExpiration: now() + 1000,
        },
      ],
      authorizedScopes: 'openid offline_access',
      refreshToken: 'rt',
      user: { sub: 'sub' },
    };

    // @ts-expect-error set custom key
    window.sessionKey = 'custom';

    await setSession(new LocalStorage(), validSession);

    const instance = testInstance({ sessionKey: 'custom' });

    expect(await instance.getSession()).toEqual(validSession);

    // @ts-expect-error set to undefined
    delete window.sessionKey;
  });
});
