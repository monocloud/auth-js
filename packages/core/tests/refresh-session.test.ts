// eslint-disable-next-line import/no-extraneous-dependencies
import { describe, expect, it } from 'vitest';
import {
  MonoCloudHttpError,
  MonoCloudOidcClient,
  MonoCloudOPError,
  MonoCloudTokenError,
  MonoCloudValidationError,
  RefreshSessionOptions,
  MonoCloudSession,
} from '../src';
import {
  fetchBuilder,
  generateIdToken,
  idTokenPublicKey,
} from '@monocloud/auth-test-utils';
import { assertError } from './utils';

describe('MonoCloudOidcClient.refreshSession()', () => {
  it('should not refresh a user session if there is no refresh token in the session', async () => {
    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessToken: 'access_token',
      scopes: 'openid',
    };
    const promise = client.refreshSession(session);

    await assertError(
      promise,
      MonoCloudValidationError,
      'Session does not contain refresh token'
    );
  });

  it('should not refresh session if refresh grant fails', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        responseCode: 400,
        error: null,
        error_description: null,
        body: 'grant_type=refresh_token&refresh_token=rt',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessToken: 'access_token',
      scopes: 'openid',
      refreshToken: 'rt',
    };

    const promise = client.refreshSession(session);

    await assertError(
      promise,
      MonoCloudOPError,
      'refresh_grant_failed',
      'Refresh token grant failed'
    );

    fetchSpy.assert();
  });

  it('should refresh a session', async () => {
    const idToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        idToken,
        body: 'grant_type=refresh_token&refresh_token=rt_old',
      })
      .configureJwks()
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const options: RefreshSessionOptions = {
      validateIdToken: true,
      idTokenClockSkew: 10,
      idTokenClockTolerance: 10,
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at_old',
          scopes: 'openid',
          accessTokenExpiration: 9999999999,
        },
      ],
      refreshToken: 'rt_old',
      idToken: idToken,
    };

    const result = await client.refreshSession(session, options);

    fetchSpy.assert();
    expect(result).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({ sub: expect.any(String) }),
        accessTokens: [
          {
            scopes: expect.any(String),
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          },
        ],
        idToken: expect.stringMatching(
          /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/
        ),
        refreshToken: 'rt',
      })
    );
  });

  it('should refresh a session specific token if matching resource and scope is specified', async () => {
    const idToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        idToken,
        body: 'grant_type=refresh_token&refresh_token=rt_target&scope=openid+old+scope&resource=https%3A%2F%2Ftarget',
        scope: 'openid new scope',
      })
      .configureJwks()
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const options: RefreshSessionOptions = {
      validateIdToken: true,
      idTokenClockSkew: 10,
      idTokenClockTolerance: 10,
      refreshGrantOptions: {
        resource: 'https://target',
        scopes: 'openid old scope',
      },
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at1',
          scopes: 'openid',
          accessTokenExpiration: 9999999999,
          resource: 'https://notaffected',
          requestedScopes: 'openid',
        },
        {
          accessToken: 'at_target',
          scopes: 'openid old scope',
          accessTokenExpiration: 9999999999,
          resource: 'https://target',
          requestedScopes: 'openid old scope',
        },
        {
          accessToken: 'at3',
          scopes: 'openid',
          accessTokenExpiration: 9999999999,
          requestedScopes: 'openid',
        },
      ],
      refreshToken: 'rt_target',
      idToken: idToken,
    };

    const result = await client.refreshSession(session, options);

    fetchSpy.assert();
    expect(result).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({ sub: expect.any(String) }),
        accessTokens: [
          {
            accessToken: 'at1',
            scopes: 'openid',
            accessTokenExpiration: 9999999999,
            resource: 'https://notaffected',
            requestedScopes: 'openid',
          },
          {
            accessToken: 'at3',
            scopes: 'openid',
            accessTokenExpiration: 9999999999,
            requestedScopes: 'openid',
          },
          {
            accessToken: 'at',
            scopes: 'openid new scope',
            accessTokenExpiration: expect.any(Number),
            resource: 'https://target',
            requestedScopes: 'openid old scope',
          },
        ],
        idToken: expect.stringMatching(
          /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/
        ),
        refreshToken: 'rt',
      })
    );
  });

  it('should refresh a session and add new token if a non existing resource and scope is specified', async () => {
    const idToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        skipIdToken: true,
        body: 'grant_type=refresh_token&refresh_token=rt_target&scope=unknown+scope&resource=https%3A%2F%2Ftargetnew',
        scope: 'unknown scope',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const options: RefreshSessionOptions = {
      validateIdToken: true,
      idTokenClockSkew: 10,
      idTokenClockTolerance: 10,
      refreshGrantOptions: {
        resource: 'https://targetnew',
        scopes: 'unknown scope',
      },
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at1',
          scopes: 'openid',
          accessTokenExpiration: 9999999999,
          resource: 'https://notaffected',
          requestedScopes: 'openid',
        },
        {
          accessToken: 'at2',
          scopes: 'unknown',
          accessTokenExpiration: 9999999999,
          resource: 'https://targetnew',
          requestedScopes: 'unknown',
        },
        {
          accessToken: 'at3',
          scopes: 'openid',
          accessTokenExpiration: 9999999999,
          requestedScopes: 'openid',
        },
      ],
      refreshToken: 'rt_target',
      idToken: idToken,
    };

    const result = await client.refreshSession(session, options);

    fetchSpy.assert();
    expect(result).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({ sub: expect.any(String) }),
        accessTokens: [
          {
            accessToken: 'at1',
            scopes: 'openid',
            accessTokenExpiration: 9999999999,
            resource: 'https://notaffected',
            requestedScopes: 'openid',
          },
          {
            accessToken: 'at2',
            scopes: 'unknown',
            accessTokenExpiration: 9999999999,
            resource: 'https://targetnew',
            requestedScopes: 'unknown',
          },
          {
            accessToken: 'at3',
            scopes: 'openid',
            accessTokenExpiration: 9999999999,
            requestedScopes: 'openid',
          },
          {
            accessToken: 'at',
            scopes: 'unknown scope',
            accessTokenExpiration: expect.any(Number),
            resource: 'https://targetnew',
            requestedScopes: 'unknown scope',
          },
        ],
        idToken: expect.stringMatching(
          /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/
        ),
        refreshToken: 'rt',
      })
    );
  });

  it('should refresh a session with jwks from the options', async () => {
    const idToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        idToken,
        body: `grant_type=refresh_token&refresh_token=refresh_token`,
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const options: RefreshSessionOptions = {
      validateIdToken: true,
      idTokenClockSkew: 10,
      idTokenClockTolerance: 10,
      jwks: { keys: [idTokenPublicKey] },
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          accessToken: 'at_old',
          scopes: 'openid',
          accessTokenExpiration: 9999999999,
        },
      ],
      refreshToken: 'refresh_token',
      idToken: idToken,
    };

    const result = await client.refreshSession(session, options);

    fetchSpy.assert();
    expect(result).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({ sub: expect.any(String) }),
        accessTokens: [
          {
            scopes: expect.any(String),
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          },
        ],
        idToken: expect.stringMatching(
          /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/
        ),
        refreshToken: 'rt',
      })
    );
  });

  it('should fail if userinfo fails', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        body: `grant_type=refresh_token&refresh_token=rt_old`,
      })
      .configureUserinfo({ responseCode: 201 })
      .createSpy();

    const options: RefreshSessionOptions = {
      fetchUserInfo: true,
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessToken: 'at_old',
      refreshToken: 'rt_old',
      scope: 'openid',
    };

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.refreshSession(session, options);

    await assertError(
      promise,
      MonoCloudHttpError,
      'Error while fetching userinfo. Unexpected status code: 201'
    );

    fetchSpy.assert();
  });

  it('should only fetch userinfo when openid scope is present', async () => {
    const idToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureUserinfo({
        claims: { sub: 'user123', username: 'username', custom: 123 },
      })
      .configureRefreshToken({
        idToken,
        body: 'grant_type=refresh_token&refresh_token=rt_old',
        scope: 'openid email',
      })
      .configureJwks()
      .createSpy();

    const options: RefreshSessionOptions = {
      fetchUserInfo: true,
    };

    let session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          scopes: 'openid email',
          accessToken: 'at_old',
          accessTokenExpiration: 9999999999999,
        },
      ],
      refreshToken: 'rt_old',
    };

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    session = await client.refreshSession(session, options);

    expect(session.user).toEqual(
      expect.objectContaining({
        sub: 'user123',
        username: 'username',
        custom: 123,
      })
    );

    fetchSpy.assert();
  });

  it('should fetch userinfo when fetch useinfo is enabled', async () => {
    const idToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .configureRefreshToken({
        idToken,
        body: 'grant_type=refresh_token&refresh_token=rt_old',
      })
      .configureUserinfo()
      .createSpy();

    const options: RefreshSessionOptions = {
      fetchUserInfo: true,
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessToken: 'at_old',
      refreshToken: 'rt_old',
      idToken,
      scope: 'openid',
    };

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    await client.refreshSession(session, options);

    fetchSpy.assert();
  });

  it('should not validate idtoken when validate idtoken option is disabled', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        idToken:
          '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
        body: 'grant_type=refresh_token&refresh_token=rt_old',
      })
      .createSpy();

    const options: RefreshSessionOptions = {
      validateIdToken: false,
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          scopes: 'openid',
          accessToken: 'at_old',
          accessTokenExpiration: 9999999999999,
        },
      ],
      refreshToken: 'rt_old',
      idToken: 'id_token',
    };

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.refreshSession(session, options);

    fetchSpy.assert();
    expect(result).toEqual(
      expect.objectContaining({
        user: {
          sub: '1234567890',
          name: 'John Doe',
        },
        accessTokens: [
          {
            scopes: 'openid offline_access',
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          },
        ],
        idToken:
          '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
        refreshToken: 'rt',
      })
    );
  });

  it('should give failed response if id token validation fails', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt_old',
      })
      .configureJwks({ jwks: [] })
      .createSpy();

    const options: RefreshSessionOptions = {
      validateIdToken: true,
      idTokenClockSkew: 0,
      idTokenClockTolerance: 0,
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessToken: 'at_old',
      refreshToken: 'rt_old',
      idToken: 'id_token',
      scope: 'openid',
    };

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.refreshSession(session, options);

    await assertError(
      promise,
      MonoCloudTokenError,
      'ID Token must have a header, payload and signature'
    );

    fetchSpy.assert();
  });

  it('should not decode invalid id token while doing refresh session(validateIdToken : false)', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        idToken: 'header.payload.signature',
        body: 'grant_type=refresh_token&refresh_token=rt_old',
      })
      .createSpy();

    const options: RefreshSessionOptions = {
      validateIdToken: false,
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessToken: 'at_old',
      refreshToken: 'rt_old',
      idToken: 'id_token',
      scope: 'openid',
    };

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.refreshSession(session, options);

    await assertError(promise, MonoCloudTokenError, 'Payload is not an object');

    fetchSpy.assert();
  });

  it('should refresh a session without id token clock skew and clock tolerance (0 for both)', async () => {
    const idToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        idToken,
        body: 'grant_type=refresh_token&refresh_token=rt_old',
      })
      .configureJwks()
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const options: RefreshSessionOptions = {
      validateIdToken: true,
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          scopes: 'openid',
          accessToken: 'at_old',
          accessTokenExpiration: 9999999999999,
        },
      ],
      refreshToken: 'rt_old',
      idToken,
    };

    const result = await client.refreshSession(session, options);

    fetchSpy.assert();
    expect(result).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({ sub: expect.any(String) }),
        accessTokens: [
          {
            scopes: 'openid offline_access',
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          },
        ],
        idToken: expect.stringMatching(
          /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/
        ),
        refreshToken: 'rt',
      })
    );
  });

  it('should refresh session without id token and userinfo', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        skipIdToken: true,
        skipRefreshToken: true,
        scope: 'openid',
        body: 'grant_type=refresh_token&refresh_token=rt_old',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const options: RefreshSessionOptions = {
      validateIdToken: true,
      idTokenClockSkew: 10,
      idTokenClockTolerance: 10,
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          scopes: 'openid',
          accessToken: 'at_old',
          accessTokenExpiration: 9999999999999,
        },
      ],
      refreshToken: 'rt_old',
    };

    const result = await client.refreshSession(session, options);

    fetchSpy.assert();
    expect(result).toEqual(
      expect.objectContaining({
        user: { sub: 'sub' },
        accessTokens: [
          {
            scopes: 'openid',
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          },
        ],
      })
    );
  });

  it('should throw error if expires_in is not present in the response', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        skipExpiration: true,
        body: 'grant_type=refresh_token&refresh_token=rt_old',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const options: RefreshSessionOptions = {
      validateIdToken: true,
      idTokenClockSkew: 10,
      idTokenClockTolerance: 10,
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          scopes: 'openid',
          accessToken: 'at_old',
          accessTokenExpiration: 9999999999999,
        },
      ],
      refreshToken: 'rt_old',
    };

    try {
      await client.refreshSession(session, options);
      throw new Error();
    } catch (error) {
      expect(error).toBeInstanceOf(MonoCloudValidationError);
      expect((error as any).message).toBe(
        "Missing required 'expires_in' field"
      );
    }

    fetchSpy.assert();
  });

  it('should throw error if scope is not present in the response', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        skipScope: true,
        body: 'grant_type=refresh_token&refresh_token=rt_old',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const options: RefreshSessionOptions = {
      validateIdToken: true,
      idTokenClockSkew: 10,
      idTokenClockTolerance: 10,
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      accessTokens: [
        {
          scopes: 'openid',
          accessToken: 'at_old',
          accessTokenExpiration: 9999999999999,
        },
      ],
      refreshToken: 'rt_old',
    };

    try {
      await client.refreshSession(session, options);
      throw new Error();
    } catch (error) {
      expect(error).toBeInstanceOf(MonoCloudValidationError);
      expect((error as any).message).toBe("Missing or invalid 'scope' field");
    }

    fetchSpy.assert();
  });

  it('should not update the authorizedScopes on refresh', async () => {
    const idToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        idToken,
        scope: 'second token',
        body: 'grant_type=refresh_token&refresh_token=rt_old&scope=second+token',
      })
      .configureJwks()
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const options: RefreshSessionOptions = {
      validateIdToken: true,
      fetchUserInfo: false,
      idTokenClockSkew: 10,
      idTokenClockTolerance: 10,
      refreshGrantOptions: {
        scopes: 'second token',
      },
    };

    const session: MonoCloudSession = {
      user: { sub: 'sub' },
      authorizedScopes:
        'this is the first set of scopes that was sent via /authorize request',
      accessTokens: [
        {
          accessToken: 'at_old',
          scopes: 'openid',
          requestedScopes: 'openid',
          accessTokenExpiration: 9999999999,
        },
        {
          accessToken: 'at_old',
          scopes: 'second token',
          requestedScopes: 'second token',
          accessTokenExpiration: 9999999999,
        },
      ],
      refreshToken: 'rt_old',
      idToken: idToken,
    };

    const result = await client.refreshSession(session, options);

    fetchSpy.assert();
    expect(result).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({ sub: expect.any(String) }),
        authorizedScopes:
          'this is the first set of scopes that was sent via /authorize request',
        accessTokens: [
          {
            accessToken: 'at_old',
            scopes: 'openid',
            requestedScopes: 'openid',
            accessTokenExpiration: 9999999999,
          },
          {
            scopes: 'second token',
            requestedScopes: 'second token',
            accessToken: 'at',
            accessTokenExpiration: expect.any(Number),
          },
        ],
        idToken: expect.stringMatching(
          /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/
        ),
        refreshToken: 'rt',
      })
    );
  });
});
