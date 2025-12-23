/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it } from 'vitest';
import {
  AuthenticateOptions,
  MonoCloudOidcClient,
  MonoCloudValidationError,
  MonoCloudHttpError,
  MonoCloudOPError,
  MonoCloudTokenError,
} from '../src';
import { fetchBuilder, generateIdToken } from '@monocloud/auth-test-utils';
import { assertError } from './utils';

describe('MonoCloudOidcClient.authenticate()', () => {
  it('should authenticate a user', async () => {
    const idToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        idToken,
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri',
      })
      .configureJwks()
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const jwks = await client.getJwks();

    const result = await client.authenticate(
      'code',
      'redirect_uri',
      'requested scope',
      undefined,
      {
        fetchUserInfo: false,
        jwks,
      }
    );

    fetchSpy.assert();
    expect(result).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({ sub: expect.any(String) }),
        accessTokens: [
          expect.objectContaining({
            accessTokenExpiration: expect.any(Number),
            accessToken: 'at',
            scopes: 'openid offline_access',
            requestedScopes: 'requested scope',
            resource: undefined,
          }),
        ],
        idToken: expect.stringMatching(
          /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/
        ),
        refreshToken: 'rt',
      })
    );
  });

  it('should authenticate a user (no id-token validation)', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        skipIdToken: true,
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri',
      })
      .configureUserinfo()
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.authenticate(
      'code',
      'redirect_uri',
      'requested scope',
      undefined,
      {
        fetchUserInfo: true,
      }
    );

    fetchSpy.assert();
    expect(result).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({ sub: expect.any(String) }),
        accessTokens: [
          expect.objectContaining({
            accessTokenExpiration: expect.any(Number),
            accessToken: 'at',
            scopes: 'openid offline_access',
            requestedScopes: 'requested scope',
            resource: undefined,
          }),
        ],
        idToken: undefined,
        refreshToken: 'rt',
      })
    );
  });

  it('should throw an error if expires_in is not present', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        skipExpiration: true,
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    try {
      await client.authenticate('code', 'redirect_uri', 'requested scope');
      throw new Error();
    } catch (error) {
      expect(error).toBeInstanceOf(MonoCloudValidationError);
      expect((error as any).message).toBe(
        "Missing required 'expires_in' field"
      );
    }

    fetchSpy.assert();
  });

  it('should throw an error if scope is not present', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        skipScope: true,
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    try {
      await client.authenticate('code', 'redirect_uri', 'requested scope');
      throw new Error();
    } catch (error) {
      expect(error).toBeInstanceOf(MonoCloudValidationError);
      expect((error as any).message).toBe("Missing or invalid 'scope' field");
    }

    fetchSpy.assert();
  });

  it('should only fetch userinfo when openid scope is present', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        scope: 'openid email',
        skipIdToken: true,
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri',
      })
      .configureUserinfo({
        claims: { sub: 'user123', username: 'username', custom: 123 },
      })
      .createSpy();

    const options: AuthenticateOptions = {
      fetchUserInfo: true,
    };

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const session = await client.authenticate(
      'code',
      'redirect_uri',
      'requested scope',
      undefined,
      options
    );

    expect(session.user).toEqual(
      expect.objectContaining({
        sub: 'user123',
        username: 'username',
        custom: 123,
      })
    );

    fetchSpy.assert();
  });

  it('should fail if userinfo fails', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri',
      })
      .configureUserinfo({ responseCode: 201 })
      .createSpy();

    const options: AuthenticateOptions = {
      fetchUserInfo: true,
    };

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.authenticate(
      'code',
      'redirect_uri',
      'requested scope',
      undefined,
      options
    );

    await assertError(
      promise,
      MonoCloudHttpError,
      'Error while fetching userinfo. Unexpected status code: 201'
    );

    fetchSpy.assert();
  });

  it('should fetch userinfo when fetch userinfo option is enabled', async () => {
    const idToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        idToken,
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri',
      })
      .configureJwks()
      .configureUserinfo()
      .createSpy();

    const options: AuthenticateOptions = {
      fetchUserInfo: true,
    };

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.authenticate(
      'code',
      'redirect_uri',
      'requested scope',
      undefined,
      options
    );

    fetchSpy.assert();
    expect(result).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({
          sub: expect.any(String),
          username: 'username',
        }),
        accessTokens: [
          expect.objectContaining({
            accessTokenExpiration: expect.any(Number),
            accessToken: 'at',
            scopes: 'openid offline_access',
            requestedScopes: 'requested scope',
            resource: undefined,
          }),
        ],
      })
    );
  });

  it('should not authenticate the user if code exchange fails', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        responseCode: 400,
        error: 'code_grant_failed',
        error_description: 'Authorization code grant failed',
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri',
      })
      .createSpy();

    const options: AuthenticateOptions = {
      fetchUserInfo: true,
    };

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.authenticate(
      'code',
      'redirect_uri',
      'requested scope',
      undefined,
      options
    );

    await assertError(
      promise,
      MonoCloudOPError,
      'code_grant_failed',
      'Authorization code grant failed'
    );

    fetchSpy.assert();
  });

  it('should not authenticate a user if get jwks fetch failed', async () => {
    const idToken = await generateIdToken();

    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        idToken,
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri',
      })
      .configureJwks({ responseCode: 201 })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.authenticate(
      'code',
      'redirect_uri',
      'requested scope'
    );

    await assertError(
      promise,
      MonoCloudHttpError,
      'Error while fetching JWKS. Unexpected status code: 201'
    );

    fetchSpy.assert();
  });

  it('should not validate id token when validate id token option is disabled', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        idToken:
          '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri',
      })
      .createSpy();

    const options: AuthenticateOptions = {
      validateIdToken: false,
    };

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.authenticate(
      'code',
      'redirect_uri',
      'requested scope',
      undefined,
      options
    );

    fetchSpy.assert();
    expect(result).toEqual(
      expect.objectContaining({
        user: {
          sub: '1234567890',
          name: 'John Doe',
        },
        idToken:
          '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
        accessTokens: [
          expect.objectContaining({
            accessTokenExpiration: expect.any(Number),
            accessToken: 'at',
            scopes: 'openid offline_access',
            requestedScopes: 'requested scope',
            resource: undefined,
          }),
        ],
      })
    );
  });

  it('should not decode a invalid id token', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        idToken: 'header.{.signature',
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri',
      })
      .createSpy();

    const options: AuthenticateOptions = {
      validateIdToken: false,
    };

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.authenticate(
      'code',
      'redirect_uri',
      'requested scope',
      undefined,
      options
    );

    await assertError(
      promise,
      MonoCloudTokenError,
      'Could not parse payload. Malformed payload'
    );

    fetchSpy.assert();
  });

  it('should not validate a invalid id token', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri',
      })
      .configureJwks()
      .createSpy();

    const options: AuthenticateOptions = {
      validateIdToken: true,
    };

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.authenticate(
      'code',
      'redirect_uri',
      'requested scope',
      undefined,
      options
    );

    await assertError(
      promise,
      MonoCloudTokenError,
      'ID Token must have a header, payload and signature'
    );

    fetchSpy.assert();
  });
});
