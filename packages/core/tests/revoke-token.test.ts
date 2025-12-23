/* eslint-disable import/no-extraneous-dependencies */
import { describe, it, vi } from 'vitest';
import {
  MonoCloudHttpError,
  MonoCloudOidcClient,
  MonoCloudOPError,
  MonoCloudValidationError,
} from '../src';
import { fetchBuilder } from '@monocloud/auth-test-utils';
import { assertError } from './utils';

describe('MonoCloudOidcClient.revokeToken()', () => {
  it('should fail if the token is invalid', async () => {
    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.revokeToken('    ', 'access_token');

    await assertError(promise, MonoCloudValidationError, 'Invalid token');
  });

  it('should fail if the token type is invalid', async () => {
    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.revokeToken('at', 'invalid');

    await assertError(
      promise,
      MonoCloudValidationError,
      'Only access_token and refresh_token types are supported.'
    );
  });

  it('should revoke tokens', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRevokeToken({ accessToken: true, tokenTypeHint: true })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    await client.revokeToken('at', 'access_token');

    fetchSpy.assert();
  });

  it('should fail if revocation fails', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRevokeToken({
        accessToken: true,
        tokenTypeHint: true,
        responseCode: 400,
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.revokeToken('at', 'access_token');

    await assertError(
      promise,
      MonoCloudOPError,
      'revocation_failed',
      'Token revocation failed'
    );

    fetchSpy.assert();
  });

  it('should fail if there is an unexpected status code', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRevokeToken({
        accessToken: true,
        tokenTypeHint: true,
        responseCode: 201,
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.revokeToken('at', 'access_token');

    await assertError(
      promise,
      MonoCloudHttpError,
      'Error while performing revocation request. Unexpected status code: 201'
    );

    fetchSpy.assert();
  });

  it('should return a failed result if the server is unreachable', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('fetch failed');
    });

    const client = new MonoCloudOidcClient('one', 'clientId');

    const promise = client.revokeToken('at');

    await assertError(promise, MonoCloudHttpError, 'fetch failed');

    fetchSpy.mockClear();
  });
});
