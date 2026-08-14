/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import {
  MonoCloudHttpError,
  MonoCloudOidcClient,
  MonoCloudOPError,
} from '../src';
import { fetchBuilder } from '@monocloud/auth-test-utils';
import { assertError } from './utils';

describe('MonoCloudOidcClient.deviceAuthorizationGrant()', () => {
  it('should perform token request at token endpoint with device code grant type', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        body: 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=device_code',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.deviceAuthorizationGrant('device_code');

    fetchSpy.assert();
    expect(result).toEqual({
      access_token: 'at',
      id_token: 'idtoken',
      refresh_token: 'rt',
      expires_in: 999,
      scope: 'openid offline_access',
      token_type: 'Bearer',
    });
  });

  it('should return a failed result if the server is unreachable', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('fetch failed');
    });

    const client = new MonoCloudOidcClient('one', 'clientId');

    const promise = client.deviceAuthorizationGrant('device_code');

    await assertError(promise, MonoCloudHttpError, 'fetch failed');

    fetchSpy.mockClear();
  });

  it.each([
    {
      error: 'authorization_pending',
      error_description: 'The authorization request is still pending',
    },
    { error: null, error_description: null },
  ])('should return a failed result if server returned a 400', async error => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        body: 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=device_code',
        ...error,
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.deviceAuthorizationGrant('device_code');

    await assertError(
      promise,
      MonoCloudOPError,
      error.error ?? 'device_token_failed',
      error.error_description ?? 'Device code token grant failed'
    );

    fetchSpy.assert();
  });

  it('should return a failed result if server returned an unexpected status code', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        responseCode: 500,
        body: 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=device_code',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.deviceAuthorizationGrant('device_code');

    await assertError(
      promise,
      MonoCloudHttpError,
      'Error while performing token grant. Unexpected status code: 500'
    );

    fetchSpy.assert();
  });

  it('should surface the oauth error when the server returns a 401', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureTokenEndpoint({
        body: 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=device_code',
        responseCode: 401,
        error: 'invalid_client',
        error_description: 'Client authentication failed',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    await assertError(
      client.deviceAuthorizationGrant('device_code'),
      MonoCloudOPError,
      'invalid_client',
      'Client authentication failed'
    );

    fetchSpy.assert();
  });
});
