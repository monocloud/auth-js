/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import { MonoCloudOidcClient } from '../src/monocloud-oidc-client';
import { fetchBuilder } from '@monocloud/auth-test-utils';
import { assertError } from './utils';
import { MonoCloudHttpError, MonoCloudOPError } from '../src';

describe('MonoCloudOidcClient.exchangeAuthorizationCode()', () => {
  it('should exchange code at token endpoint', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri&code_verifier=xyz&resource=https%3A%2F%2Fresource.com',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.exchangeAuthorizationCode(
      'code',
      'redirect_uri',
      'xyz',
      'https://resource.com'
    );

    fetchSpy.assert();
    expect(result).toEqual({
      access_token: 'at',
      id_token: 'idtoken',
      expires_in: 999,
      refresh_token: 'rt',
      scope: 'openid offline_access',
      token_type: 'Bearer',
    });
  });

  it.each([
    {
      error: 'some_unknown_error',
      error_description: 'Some unknwon error occured',
    },
    {
      error: null,
      error_description: null,
    },
  ])('should return a failed result if server returned a 400', async e => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri&code_verifier=xyz',
        error: e.error,
        error_description: e.error_description,
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.exchangeAuthorizationCode(
      'code',
      'redirect_uri',
      'xyz'
    );

    await assertError(
      promise,
      MonoCloudOPError,
      e.error ?? 'code_grant_failed',
      e.error_description ?? 'Authorization code grant failed'
    );
    fetchSpy.assert();
  });

  it('should return a failed response if the server is unreachable', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('fetch failed');
    });

    const client = new MonoCloudOidcClient('.com', 'clientId');

    const promise = client.exchangeAuthorizationCode(
      'code',
      'redirect_uri',
      'xyz'
    );

    await assertError(promise, MonoCloudHttpError, 'fetch failed');

    fetchSpy.mockClear();
  });

  it('should return a failed response if the server returned unexpected status code', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        body: 'grant_type=authorization_code&code=code&redirect_uri=redirect_uri&code_verifier=xyz',
        responseCode: 500,
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.exchangeAuthorizationCode(
      'code',
      'redirect_uri',
      'xyz'
    );

    await assertError(
      promise,
      MonoCloudHttpError,
      'Error while performing token grant. Unexpected status code: 500'
    );

    fetchSpy.assert();
  });
});
