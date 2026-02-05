// // eslint-disable-next-line import/no-extraneous-dependencies
// import { afterEach, beforeEach, describe, expect, it } from 'vitest';
// import { fetchBuilder } from '@monocloud/auth-test-utils';
// import { now } from '@monocloud/auth-core/internal';
// import type { MonoCloudSession } from '@monocloud/auth-core';
// import { MonoCloudValidationError } from '@monocloud/auth-core';
// import { setSession, testInstance, VanillaJsMockStorage } from './utils';

// describe('getTokens() Tests', () => {
//   let mockStorage: VanillaJsMockStorage;

//   beforeEach(() => {
//     mockStorage = new VanillaJsMockStorage();

//     if (!(globalThis as any).LockManager) {
//       (globalThis as any).LockManager = class LockManager {};
//     }

//     (globalThis as any).navigator = (globalThis as any).navigator ?? {};
//   });

//   afterEach(() => {
//     window.localStorage.clear();
//     window.sessionStorage.clear();
//   });

//   it('should throw if session does not exist', async () => {
//     const instance = testInstance({ storage: mockStorage });

//     const error = await instance.getTokens().catch(e => e);

//     expect(error).toBeInstanceOf(MonoCloudValidationError);
//     expect(error.message).toBe('Session does not exist');
//   });

//   it('should return existing token without refresh when it is not expired', async () => {
// const session: MonoCloudSession = {
//   idToken: 'idToken',
//   refreshToken: 'rt',
//   authorizedScopes: 'openid offline_access',
//   user: { sub: 'sub' },
//   accessTokens: [
//     {
//       accessToken: 'at',
//       accessTokenExpiration: now() + 1000,
//       scopes: 'openid offline_access',
//       requestedScopes: 'openid offline_access',
//     },
//   ],
// };

// setSession(mockStorage, session);

// const instance = testInstance({ storage: mockStorage });

// const tokens = await instance.getTokens();

// expect(tokens).toEqual(
//   expect.objectContaining({
//     accessToken: 'at',
//     accessTokenExpiration: expect.any(Number),
//     scopes: 'openid offline_access',
//     requestedScopes: 'openid offline_access',
//     idToken: 'idToken',
//     refreshToken: 'rt',
//     isExpired: false,
//   })
// );
//   });

//   it('should refresh when token is expired', async () => {
//     const fetchSpy = fetchBuilder()
//       .configureMetadata()
//       .configureRefreshToken({
//         body: 'grant_type=refresh_token&refresh_token=rt',
//         accessToken: 'newAt',
//         refreshToken: 'newRt',
//         scope: 'openid offline_access',
//         skipIdToken: true,
//       })
//       .createSpy();

//     const session: MonoCloudSession = {
//       idToken: 'oldId',
//       refreshToken: 'rt',
//       authorizedScopes: 'openid offline_access',
//       user: { sub: 'sub' },
//       accessTokens: [
//         {
//           accessToken: 'at',
//           accessTokenExpiration: now() + 10,
//           scopes: 'openid offline_access',
//           requestedScopes: 'openid offline_access',
//         },
//       ],
//     };

//     setSession(mockStorage, session);

//     const instance = testInstance({ storage: mockStorage });

//     const tokens = await instance.getTokens();

//     expect(tokens).toEqual(
//       expect.objectContaining({
//         accessToken: 'newAt',
//         refreshToken: 'newRt',
//         idToken: 'oldId',
//         isExpired: false,
//       })
//     );

//     fetchSpy.assert();
//   });

//   it('should refresh when forceRefresh is true even if token is not expired', async () => {
//     const fetchSpy = fetchBuilder()
//       .configureMetadata()
//       .configureRefreshToken({
//         body: 'grant_type=refresh_token&refresh_token=rt',
//         accessToken: 'newAt',
//         refreshToken: 'newRt',
//         scope: 'openid offline_access',
//         skipIdToken: true,
//       })
//       .createSpy();

//     const session: MonoCloudSession = {
//       idToken: 'oldId',
//       refreshToken: 'rt',
//       authorizedScopes: 'openid offline_access',
//       user: { sub: 'sub' },
//       accessTokens: [
//         {
//           accessToken: 'at',
//           accessTokenExpiration: now() + 1000,
//           scopes: 'openid offline_access',
//           requestedScopes: 'openid offline_access',
//         },
//       ],
//     };

//     setSession(mockStorage, session);

//     const instance = testInstance({ storage: mockStorage });

//     const tokens = await instance.getTokens({ forceRefresh: true });

//     expect(tokens.accessToken).toBe('newAt');
//     expect(tokens.refreshToken).toBe('newRt');

//     fetchSpy.assert();
//   });

//   it('should resolve scopes from options.resources when resource is provided without scopes, then refresh using those scopes', async () => {
//     const fetchSpy = fetchBuilder()
//       .configureMetadata()
//       .configureRefreshToken({
//         body: 'grant_type=refresh_token&refresh_token=rt&scope=api.read&resource=api',
//         accessToken: 'newAt',
//         refreshToken: 'newRt',
//         scope: 'api.read',
//         skipIdToken: true,
//       })
//       .createSpy();

//     const session: MonoCloudSession = {
//       idToken: 'oldId',
//       refreshToken: 'rt',
//       authorizedScopes: 'openid offline_access',
//       user: { sub: 'sub' },
//       accessTokens: [
//         {
//           accessToken: 'at',
//           accessTokenExpiration: now() + 1000,
//           scopes: 'openid offline_access',
//           requestedScopes: 'openid offline_access',
//         },
//       ],
//     };

//     setSession(mockStorage, session);

//     const instance = testInstance({
//       storage: mockStorage,
//       resources: [{ resource: 'api', scopes: 'api.read' }],
//     });

//     const tokens = await instance.getTokens({ resource: 'api' });

//     expect(tokens).toEqual(
//       expect.objectContaining({
//         accessToken: 'newAt',
//         refreshToken: 'newRt',
//         requestedScopes: 'api.read',
//         scopes: 'api.read',
//       })
//     );

//     fetchSpy.assert();
//   });

//   it('should not infer scopes if a no-scope resource entry exists (resource match with scopes undefined)', async () => {
//     const fetchSpy = fetchBuilder()
//       .configureMetadata()
//       .configureRefreshToken({
//         body: 'grant_type=refresh_token&refresh_token=rt&resource=api',
//         accessToken: 'newAt',
//         refreshToken: 'newRt',
//         scope: 'openid',
//         skipIdToken: true,
//       })
//       .createSpy();

//     const session: MonoCloudSession = {
//       idToken: 'oldId',
//       refreshToken: 'rt',
//       authorizedScopes: 'openid offline_access',
//       user: { sub: 'sub' },
//       accessTokens: [
//         {
//           accessToken: 'at',
//           accessTokenExpiration: now() + 1000,
//           scopes: 'openid offline_access',
//           requestedScopes: 'openid offline_access',
//         },
//       ],
//     };

//     setSession(mockStorage, session);

//     const instance = testInstance({
//       storage: mockStorage,
//       resources: [{ resource: 'api' }, { resource: 'api', scopes: 'api.read' }],
//     });

//     const tokens = await instance.getTokens({
//       resource: 'api',
//       forceRefresh: true,
//     });

//     expect(tokens.accessToken).toBe('newAt');
//     fetchSpy.assert();
//   });
// });

// eslint-disable-next-line import/no-extraneous-dependencies
/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-param-reassign */
/* eslint-disable @typescript-eslint/no-non-null-assertion */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fetchBuilder, generateIdToken } from '@monocloud/auth-test-utils';
import { now } from '@monocloud/auth-core/internal';
import {
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

    // 2. Prepare Data
    const originalIdToken = await generateIdToken({
      claims: { sub: 'test-user', aud: 'clientId', nonce: 'original-nonce' },
    });

    // New ID Token (No nonce)
    const newIdToken = await generateIdToken({
      claims: { sub: 'test-user', aud: 'clientId' },
    });

    // 3. Setup Fetch Mock
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt',
        accessToken: 'at1',
        refreshToken: 'rt1',
        idToken: newIdToken,
        scope: 'openid something',
        expires_in: 999,
      })
      .createSpy();

    // 4. Setup Initial Session
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

    // 5. Initialize Instance with onSessionCreating hook
    const instance = testInstance({
      storage: mockStorage,
      // Hook logic from your source test
      onSessionCreating: async (session, idtoken, userinfo, appState) => {
        expect(appState).toBeUndefined();
        expect(userinfo).toBeUndefined();
        expect(idtoken).toBeDefined();

        // Modify the session
        (session as any).custom = 1;
      },
    });

    const newFrozenTime = frozenTimeMs + 2000;
    travel(newFrozenTime);

    // 7. Act: Force Refresh
    const tokens = await instance.getTokens({ forceRefresh: true });

    // 8. Assert: Returned tokens are correct
    expect(tokens).toEqual({
      accessToken: 'at1',
      scopes: 'openid something',
      accessTokenExpiration: expect.any(Number),
      idToken: newIdToken,
      refreshToken: 'rt1',
      requestedScopes: 'openid abc',
      isExpired: false,
    });

    // 9. Assert: Session Storage contains the custom modification
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
        // ✅ Verified: The custom property added by the hook is present
        custom: 1,
      })
    );

    fetchSpy.assert();
  });
});
