/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import { MonoCloudOidcClient } from '../src/monocloud-oidc-client';
import { fetchBuilder } from '@monocloud/auth-test-utils';
import { assertError } from './utils';
import { MonoCloudHttpError, MonoCloudOPError } from '../src';

describe('MonoCloudOidcClient.refreshGrant()', () => {
  it('should perform the refresh token grant at token endpoint', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt&scope=api1+api2&resource=resource1&resource=resource2',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.refreshGrant('rt', {
      resource: 'resource1 resource2',
      scopes: 'api1 api2',
    });

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

  it('should return a failed result if server is unreachable', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('fetch failed');
    });

    const client = new MonoCloudOidcClient('example', 'clientId');

    const promise = client.refreshGrant('rt');

    await assertError(promise, MonoCloudHttpError, 'fetch failed');

    fetchSpy.mockClear();
  });

  it('should return a failed result if server returned an unexpected status code', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        responseCode: 500,
        body: 'grant_type=refresh_token&refresh_token=rt',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.refreshGrant('rt');

    await assertError(
      promise,
      MonoCloudHttpError,
      `Error while performing refresh token grant. Unexpected status code: 500`
    );

    fetchSpy.assert();
  });

  it.each([
    {
      error: 'some_unkown_error',
      error_description: 'Some unkown error occured',
    },
    { error: null, error_description: null },
  ])('should return a failed result if server returned a 400', async error => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        responseCode: 400,
        body: 'grant_type=refresh_token&refresh_token=rt',
        ...error,
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.refreshGrant('rt');

    await assertError(
      promise,
      MonoCloudOPError,
      error.error ?? 'refresh_grant_failed',
      error.error_description ?? 'Refresh token grant failed'
    );

    fetchSpy.assert();
  });
});
