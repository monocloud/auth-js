// eslint-disable-next-line import/no-extraneous-dependencies
/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-param-reassign */
/* eslint-disable @typescript-eslint/no-non-null-assertion */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fetchBuilder, generateIdToken } from '@monocloud/auth-test-utils';
import { now } from '@monocloud/auth-core/internal';
import {
  MonoCloudHttpError,
  MonoCloudValidationError,
  type MonoCloudSession,
  type MonoCloudUser,
} from '@monocloud/auth-core';
import { setSession, testInstance, VanillaJsMockStorage } from './utils';
import { freeze, travel } from 'timekeeper';

describe('getTokens() Tests', () => {
  let mockStorage: VanillaJsMockStorage;

  beforeEach(() => {
    mockStorage = new VanillaJsMockStorage();

    if (!(globalThis as any).LockManager) {
      (globalThis as any).LockManager = class LockManager {};
    }

    (globalThis as any).navigator = (globalThis as any).navigator ?? {};
  });

  afterEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it('should return the tokens', async () => {
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

    setSession(mockStorage, session);
    const instance = testInstance({ storage: mockStorage });

    const tokens = await instance.getTokens();

    expect(tokens).toEqual({
      accessToken: 'at',
      accessTokenExpiration: expect.any(Number),
      scopes: 'openid offline_access',
      requestedScopes: 'openid offline_access',
      idToken: 'idToken',
      refreshToken: 'rt',
      isExpired: false,
    });
  });

  it('should find the token with the resource from session', async () => {
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
          resource: 'https://resource.com',
        },
      ],
    };

    setSession(mockStorage, session);
    const instance = testInstance({ storage: mockStorage });

    const tokens = await instance.getTokens({
      resource: 'https://resource.com',
      scopes: 'openid offline_access',
    });

    expect(tokens).toEqual({
      accessToken: 'at',
      accessTokenExpiration: expect.any(Number),
      scopes: 'openid offline_access',
      requestedScopes: 'openid offline_access',
      resource: 'https://resource.com',
      idToken: 'idToken',
      refreshToken: 'rt',
      isExpired: false,
    });
  });

  it('should find the token with the undefined scopes', async () => {
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
          requestedScopes: undefined,
          resource: 'https://resource.com',
        },
      ],
    };

    setSession(mockStorage, session);

    const instance = testInstance({
      storage: mockStorage,
      resources: [{ resource: 'https://resource.com' }],
    });

    const tokens = await instance.getTokens({
      resource: 'https://resource.com',
    });

    expect(tokens).toEqual({
      accessToken: 'at',
      scopes: 'openid offline_access',
      resource: 'https://resource.com',
      accessTokenExpiration: expect.any(Number),
      idToken: 'idToken',
      refreshToken: 'rt',
      isExpired: false,
    });
  });

  it('should find the token with scopes defined in indicator options', async () => {
    const session: MonoCloudSession = {
      user: {} as MonoCloudUser,
      authorizedScopes: 'openid abc',
      accessTokens: [
        {
          scopes: 'openid abc',
          requestedScopes: 'openid abc',
          accessToken: 'at',
          resource: 'https://resource.com',
          accessTokenExpiration: now() + 100,
        },
      ],
      idToken: 'idtoken',
      refreshToken: 'rt',
    };

    setSession(mockStorage, session);

    const instance = testInstance({
      storage: mockStorage,
      resources: [{ resource: 'https://resource.com', scopes: 'openid abc' }],
    });

    const tokens = await instance.getTokens({
      resource: 'https://resource.com',
    });

    expect(tokens).toEqual({
      accessToken: 'at',
      scopes: 'openid abc',
      requestedScopes: 'openid abc',
      resource: 'https://resource.com',
      accessTokenExpiration: expect.any(Number),
      idToken: 'idtoken',
      refreshToken: 'rt',
      isExpired: false,
    });
  });

  it('should refresh the tokens if forceRefresh is specified', async () => {
    const frozenTimeMs = 1330688329321;
    freeze(frozenTimeMs);

    const originalIdToken = await generateIdToken({
      claims: { sub: 'test-user', aud: 'clientId', nonce: 'original-nonce' },
    });

    const newIdToken = await generateIdToken({
      claims: { sub: 'test-user', aud: 'clientId' },
    });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt',
        accessToken: 'at1',
        refreshToken: 'rt1',
        idToken: newIdToken,
        scope: 'something',
      })
      .createSpy();

    const session: MonoCloudSession = {
      user: { sub: 'test-user' },
      idToken: originalIdToken,
      refreshToken: 'rt',
      authorizedScopes: 'something',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 100,
          scopes: 'something',
          requestedScopes: 'something',
        },
      ],
    };

    await setSession(mockStorage, session);

    const instance = testInstance({ storage: mockStorage });

    const newFrozenTime = frozenTimeMs + 2000;
    travel(newFrozenTime);

    const tokens = await instance.getTokens({ forceRefresh: true });

    expect(tokens).toEqual({
      accessToken: 'at1',
      accessTokenExpiration: expect.any(Number),
      idToken: newIdToken,
      refreshToken: 'rt1',
      scopes: 'something',
      requestedScopes: 'something',
      isExpired: false,
    });

    const updatedSession = await instance.getSession();

    expect(updatedSession).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({ sub: 'test-user' }),
        idToken: newIdToken,
        refreshToken: 'rt1',
        accessTokens: [
          expect.objectContaining({
            accessToken: 'at1',
            scopes: 'something',
          }),
        ],
      })
    );

    fetchSpy.assert();
  });

  it('should not save the new access token in the cookie if RefreshGrantOptions.scopes or RefreshGrantOptions.resource was passed in', async () => {
    const frozenTimeMs = 1330688329321;
    freeze(frozenTimeMs);

    const originalIdToken = await generateIdToken({
      claims: { sub: 'test-user', aud: 'clientId', nonce: 'original-nonce' },
    });

    const newIdToken = await generateIdToken({
      claims: { sub: 'test-user', aud: 'clientId' },
    });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt',
        accessToken: 'at1',
        refreshToken: 'rt1',
        idToken: newIdToken,
        scope: 'something',
      })
      .createSpy();

    const session: MonoCloudSession = {
      user: { sub: 'test-user' },
      idToken: originalIdToken,
      refreshToken: 'rt',
      authorizedScopes: 'something',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 100,
          scopes: 'abc',
          requestedScopes: 'something',
        },
      ],
    };

    await setSession(mockStorage, session);

    const instance = testInstance({ storage: mockStorage });

    const newFrozenTime = frozenTimeMs + 2000;
    travel(newFrozenTime);

    const tokens = await instance.getTokens({ forceRefresh: true });

    expect(tokens).toEqual({
      accessToken: 'at1',
      accessTokenExpiration: expect.any(Number),
      idToken: newIdToken,
      refreshToken: 'rt1',
      scopes: 'something',
      requestedScopes: 'something',
      isExpired: false,
    });

    const updatedSession = await instance.getSession();

    expect(updatedSession).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({ sub: 'test-user' }),
        idToken: newIdToken,
        refreshToken: 'rt1',
        accessTokens: [
          expect.objectContaining({
            accessToken: 'at1',
            scopes: 'something',
          }),
        ],
      })
    );

    fetchSpy.assert();
  });

  it('should throw error if force refresh is true and no refresh token is found', async () => {
    const session: MonoCloudSession = {
      user: { sub: 'test-user' },
      idToken: 'idtoken',
      refreshToken: undefined,
      authorizedScopes: 'abc',
      accessTokens: [
        {
          scopes: 'abc',
          accessToken: 'at',
          accessTokenExpiration: now() + 100,
        },
      ],
    };

    await setSession(mockStorage, session);

    const instance = testInstance({ storage: mockStorage });

    const tokensPromise = instance.getTokens({ forceRefresh: true });

    await expect(tokensPromise).rejects.toBeInstanceOf(
      MonoCloudValidationError
    );

    await expect(tokensPromise).rejects.toThrow(
      'Session does not contain refresh token'
    );
  });

  it('should refresh the tokens and fetch from userinfo using the new access token if specified', async () => {
    const frozenTimeMs = 1330688329321;
    freeze(frozenTimeMs);

    const originalIdToken = await generateIdToken({
      claims: { sub: 'test-user', aud: 'clientId', nonce: 'original-nonce' },
    });

    const newIdToken = await generateIdToken({
      claims: { sub: 'test-user', aud: 'clientId' },
    });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt',
        accessToken: 'at1',
        refreshToken: 'rt1',
        idToken: newIdToken,
        scope: 'openid abc',
      })
      .configureUserinfo({
        accessToken: 'at1',
        claims: {
          sub: 'test-user',
          username: 'oooooooooosername',
          test: '123',
          test2: '1234',
        },
      })
      .createSpy();

    const session: MonoCloudSession = {
      user: { sub: 'test-user' },
      idToken: originalIdToken,
      refreshToken: 'rt',
      authorizedScopes: 'openid abc',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 100,
          scopes: 'openid abc',
          requestedScopes: 'openid abc',
        },
      ],
    };

    await setSession(mockStorage, session);

    const instance = testInstance({ storage: mockStorage });

    const newFrozenTime = frozenTimeMs + 2000;
    travel(newFrozenTime);

    const tokens = await instance.getTokens({
      forceRefresh: true,
      refetchUserInfo: true,
    });

    expect(tokens).toEqual({
      accessToken: 'at1',
      accessTokenExpiration: expect.any(Number),
      idToken: newIdToken,
      refreshToken: 'rt1',
      scopes: 'openid abc',
      requestedScopes: 'openid abc',
      isExpired: false,
    });

    const updatedSession = await instance.getSession();

    expect(updatedSession).toMatchObject({
      user: {
        sub: 'test-user',
        username: 'oooooooooosername',
        test: '123',
        test2: '1234',
      },
      idToken: newIdToken,
      refreshToken: 'rt1',
      accessTokens: [
        {
          accessToken: 'at1',
          scopes: 'openid abc',
        },
      ],
    });

    fetchSpy.assert();
  });

  it('should save with the old refresh token if the updated token response does not have one', async () => {
    const frozenTimeMs = 1330688329321;
    freeze(frozenTimeMs);

    const originalIdToken = await generateIdToken({
      claims: { sub: 'test-user', aud: 'clientId', nonce: 'original-nonce' },
    });

    const newIdToken = await generateIdToken({
      claims: { sub: 'test-user', aud: 'clientId' },
    });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt',
        accessToken: 'at1',
        idToken: newIdToken,
        scope: 'something',
        refreshToken: undefined,
      })
      .createSpy();

    const session: MonoCloudSession = {
      user: { sub: 'test-user' },
      idToken: originalIdToken,
      refreshToken: 'rt',
      authorizedScopes: 'abc',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 100,
          scopes: 'abc',
          requestedScopes: 'abc',
        },
      ],
    };

    await setSession(mockStorage, session);

    const instance = testInstance({ storage: mockStorage });

    const newFrozenTime = frozenTimeMs + 2000;
    travel(newFrozenTime);

    const tokens = await instance.getTokens({ forceRefresh: true });

    expect(tokens).toEqual({
      accessToken: 'at1',
      accessTokenExpiration: expect.any(Number),
      idToken: newIdToken,
      refreshToken: 'rt',
      scopes: 'something',
      requestedScopes: 'abc',
      resource: undefined,
      isExpired: false,
    });

    const updatedSession = await instance.getSession();

    expect(updatedSession).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({ sub: 'test-user' }),
        idToken: newIdToken,
        refreshToken: 'rt',
        accessTokens: [
          expect.objectContaining({
            accessToken: 'at1',
            scopes: 'something',
          }),
        ],
      })
    );

    fetchSpy.assert();
  });

  it('should be able to customize the session using onSessionCreating', async () => {
    const frozenTimeMs = 1330688329321;
    freeze(frozenTimeMs);

    const originalIdToken = await generateIdToken({
      claims: { sub: 'test-user', aud: 'clientId', nonce: 'original-nonce' },
    });

    const newIdToken = await generateIdToken({
      claims: { sub: 'test-user', aud: 'clientId' },
    });

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt',
        accessToken: 'at1',
        refreshToken: 'rt1',
        idToken: newIdToken,
        scope: 'openid something',
      })
      .createSpy();

    const initialSession: MonoCloudSession = {
      user: { sub: 'test-user' },
      idToken: originalIdToken,
      refreshToken: 'rt',
      authorizedScopes: 'openid abc',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 100,
          scopes: 'openid abc',
          requestedScopes: 'openid abc',
        },
      ],
    };

    await setSession(mockStorage, initialSession);

    const instance = testInstance({
      storage: mockStorage,
      onSessionCreating: async (session, idtoken, userinfo, appState) => {
        expect(appState).toBeUndefined();
        expect(userinfo).toBeUndefined();
        expect(idtoken).toBeDefined();

        (session as any).custom = 1;
      },
    });

    const newFrozenTime = frozenTimeMs + 2000;
    travel(newFrozenTime);

    const tokens = await instance.getTokens({ forceRefresh: true });

    expect(tokens).toEqual({
      accessToken: 'at1',
      scopes: 'openid something',
      accessTokenExpiration: expect.any(Number),
      idToken: newIdToken,
      refreshToken: 'rt1',
      requestedScopes: 'openid abc',
      isExpired: false,
    });

    const updatedSession = await instance.getSession();

    expect(updatedSession).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({ sub: 'test-user' }),
        idToken: newIdToken,
        refreshToken: 'rt1',
        accessTokens: [
          expect.objectContaining({
            accessToken: 'at1',
            scopes: 'openid something',
          }),
        ],
        custom: 1,
      })
    );

    fetchSpy.assert();
  });

  it('should throw if session is not found', async () => {
    await mockStorage.clear();

    const instance = testInstance({ storage: mockStorage });

    const tokensPromise = instance.getTokens();

    await expect(tokensPromise).rejects.toBeInstanceOf(
      MonoCloudValidationError
    );
    await expect(tokensPromise).rejects.toThrow('Session does not exist');
  });

  it('should throw error if refresh grant fails', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        responseCode: 400,
        error: 'some_error_code',
        error_description: 'errorDescription',
      })
      .createSpy();

    const session: MonoCloudSession = {
      user: { sub: 'test-user' },
      idToken: 'idtoken',
      refreshToken: 'rt',
      authorizedScopes: 'abc',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 100,
          scopes: 'abc',
          requestedScopes: 'abc',
        },
      ],
    };

    await setSession(mockStorage, session);

    const instance = testInstance({ storage: mockStorage });

    const tokensPromise = instance.getTokens({ forceRefresh: true });

    await expect(tokensPromise).rejects.toThrow('some_error_code');
    await expect(tokensPromise).rejects.toMatchObject({
      error: 'some_error_code',
      errorDescription: 'errorDescription',
    });

    fetchSpy.assert();
  });

  it('should throw error if userinfo fails', async () => {
    const newIdToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt',
        accessToken: 'at1',
        refreshToken: 'rt1',
        idToken: newIdToken,
        scope: 'openid something',
      })
      .configureUserinfo({
        accessToken: 'at1',
        responseCode: 400,
        claims: {
          error: 'error',
          error_description: 'errorDescription',
        },
      })
      .createSpy();

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          scopes: 'openid abc',
          accessToken: 'at',
          accessTokenExpiration: now() + 100,
        },
      ],
      idToken: 'idtoken',
      refreshToken: 'rt',
      authorizedScopes: 'openid abc',
    };

    await setSession(mockStorage, session);

    const instance = testInstance({
      storage: mockStorage,
      fetchUserinfo: true,
    });

    const tokensPromise = instance.getTokens({
      forceRefresh: true,
      refetchUserInfo: true,
    });

    await expect(tokensPromise).rejects.toThrow(MonoCloudHttpError);
    await expect(tokensPromise).rejects.toThrow(
      'Error while fetching userinfo. Unexpected status code: 400'
    );

    fetchSpy.assert();
  });

  it('should throw error if jwks fetch fails', async () => {
    const newIdToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt',
        accessToken: 'at1',
        refreshToken: 'rt1',
        idToken: newIdToken,
        scope: 'openid something',
      })
      .configureJwks({
        responseCode: 400,
      })
      .createSpy();

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          scopes: 'abc',
          accessToken: 'at',
          accessTokenExpiration: now() + 100,
        },
      ],
      idToken: 'idtoken',
      refreshToken: 'rt',
      authorizedScopes: 'abc',
    };

    await setSession(mockStorage, session);

    const instance = testInstance({
      storage: mockStorage,
      fetchUserinfo: false,
    });

    const tokensPromise = instance.getTokens({ forceRefresh: true });

    await expect(tokensPromise).rejects.toThrow(MonoCloudHttpError);
    await expect(tokensPromise).rejects.toThrow(
      'Error while fetching JWKS. Unexpected status code: 400'
    );

    fetchSpy.assert();
  });

  it('should throw error if id token validation fails', async () => {
    const validIdToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt',
        accessToken: 'at1',
        refreshToken: 'rt1',
        idToken: 'malformed_token_string',
        scope: 'openid something',
      })
      .createSpy();

    const session: MonoCloudSession = {
      user: { sub: 'test-user' },
      accessTokens: [
        {
          scopes: 'abc',
          accessToken: 'at',
          accessTokenExpiration: now() + 100,
        },
      ],
      idToken: validIdToken,
      refreshToken: 'rt',
      authorizedScopes: 'abc',
    };

    await setSession(mockStorage, session);

    const instance = testInstance({ storage: mockStorage });

    const tokensPromise = instance.getTokens({ forceRefresh: true });

    await expect(tokensPromise).rejects.toThrow(
      'ID Token must have a header, payload and signature'
    );

    fetchSpy.assert();
  });
});
