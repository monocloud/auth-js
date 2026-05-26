// eslint-disable-next-line import/no-extraneous-dependencies
import { describe, it, expect, afterEach, vi } from 'vitest';
import type { MonoCloudSession } from '@monocloud/auth-core';
import { now } from '@monocloud/auth-core/internal';
import { setSession, testInstance } from './utils';
import { LocalStorage } from '../src';

describe('Session Tests', () => {
  afterEach(() => {
    window.localStorage.clear();
    vi.restoreAllMocks();
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

  it('should propagate the parse error without clearing when stored session is corrupted', async () => {
    const storage = new LocalStorage();
    await storage.setItem('mc.session.clientId', '{ malformed_json');

    const instance = testInstance();

    await expect(instance.getSession()).rejects.toThrowError(SyntaxError);
    expect(await storage.getItem('mc.session.clientId')).toBe(
      '{ malformed_json'
    );
  });

  it('should propagate storage.getItem errors without clearing the session', async () => {
    vi.spyOn(window.localStorage, 'getItem').mockImplementation(() => {
      throw new Error('quota exceeded');
    });
    const removeSpy = vi.spyOn(window.localStorage, 'removeItem');

    const instance = testInstance();

    await expect(instance.getSession()).rejects.toThrow('quota exceeded');
    expect(removeSpy).not.toHaveBeenCalled();
  });
});
