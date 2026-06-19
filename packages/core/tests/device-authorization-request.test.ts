/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import {
  MonoCloudHttpError,
  MonoCloudOidcClient,
  MonoCloudOPError,
} from '../src';
import { fetchBuilder } from '@monocloud/auth-test-utils';
import { assertError } from './utils';

describe('MonoCloudOidcClient.deviceAuthorizationRequest()', () => {
  it('should perform request at device authorization endpoint with scopes and resource', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureDeviceAuthorization({
        body: 'client_id=clientId&scope=openid+api&resource=resource1&resource=resource2',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.deviceAuthorizationRequest({
      scopes: 'openid api',
      resource: 'resource1 resource2',
    });

    fetchSpy.assert();
    expect(result).toEqual({
      device_code: 'device_code',
      user_code: 'user_code',
      verification_uri: 'https://example.com/device',
      verification_uri_complete:
        'https://example.com/device?user_code=user_code',
      expires_in: 1800,
      interval: 5,
    });
  });

  it('should perform request at device authorization endpoint without resource', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureDeviceAuthorization({
        body: 'client_id=clientId&scope=openid',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.deviceAuthorizationRequest({
      scopes: 'openid',
    });

    fetchSpy.assert();
    expect(result).toEqual({
      device_code: 'device_code',
      user_code: 'user_code',
      verification_uri: 'https://example.com/device',
      verification_uri_complete:
        'https://example.com/device?user_code=user_code',
      expires_in: 1800,
      interval: 5,
    });
  });

  it('should perform request at device authorization endpoint without scopes', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureDeviceAuthorization({
        body: 'client_id=clientId',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.deviceAuthorizationRequest({});

    fetchSpy.assert();
    expect(result).toEqual({
      device_code: 'device_code',
      user_code: 'user_code',
      verification_uri: 'https://example.com/device',
      verification_uri_complete:
        'https://example.com/device?user_code=user_code',
      expires_in: 1800,
      interval: 5,
    });
  });

  it('should return a failed result if the server is unreachable', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('fetch failed');
    });

    const client = new MonoCloudOidcClient('one', 'clientId');

    const promise = client.deviceAuthorizationRequest({ scopes: 'openid' });

    await assertError(promise, MonoCloudHttpError, 'fetch failed');

    fetchSpy.mockClear();
  });

  it.each([
    {
      error: 'invalid_client',
      error_description: 'Client authentication failed',
    },
    { error: null, error_description: null },
  ])('should return a failed result if server returned a 400', async error => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureDeviceAuthorization({
        body: 'client_id=clientId&scope=openid',
        ...error,
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.deviceAuthorizationRequest({ scopes: 'openid' });

    await assertError(
      promise,
      MonoCloudOPError,
      error.error ?? 'device_authorization_failed',
      error.error_description ?? 'Device Authorization Request Failed'
    );

    fetchSpy.assert();
  });

  it('should return a failed result if server returned an unexpected status code', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureDeviceAuthorization({
        responseCode: 500,
        body: 'client_id=clientId&scope=openid',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.deviceAuthorizationRequest({ scopes: 'openid' });

    await assertError(
      promise,
      MonoCloudHttpError,
      'Error while performing device authorization request. Unexpected status code: 500'
    );

    fetchSpy.assert();
  });
});
