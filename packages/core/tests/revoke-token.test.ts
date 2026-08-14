/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import {
  MonoCloudHttpError,
  MonoCloudOidcClient,
  MonoCloudOPError,
  MonoCloudValidationError,
} from '../src';
import { fetchBuilder, mtlsFetchSpy } from '@monocloud/auth-test-utils';
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

  it('should revoke at the mTLS revocation endpoint alias for mTLS auth methods', async () => {
    const fetchSpy = mtlsFetchSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId', {
      clientAuthMethod: 'tls_client_auth',
    });

    await client.revokeToken('at', 'access_token');

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://mtls.example.com/connect/revocation',
      expect.objectContaining({ method: 'POST' })
    );

    fetchSpy.mockClear();
  });

  it('should surface the oauth error when the server returns a 401', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRevokeToken({
        accessToken: true,
        tokenTypeHint: true,
        responseCode: 401,
        error: 'invalid_client',
        error_description: 'Client authentication failed',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    await assertError(
      client.revokeToken('at', 'access_token'),
      MonoCloudOPError,
      'invalid_client',
      'Client authentication failed'
    );

    fetchSpy.assert();
  });
});
