/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import {
  MonoCloudHttpError,
  MonoCloudOidcClient,
  MonoCloudOPError,
  MonoCloudValidationError,
} from '../src';
import { fetchBuilder } from '@monocloud/auth-test-utils';
import { assertError } from './utils';

describe('MonoCloudOidcClient.userinfo()', () => {
  it('should fetch userinfo', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureUserinfo({ claims: { sub: 'userinfo' } })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.userinfo('at');

    fetchSpy.assert();
    expect(result).toEqual({ sub: 'userinfo' });
  });

  it('should give a failure result if the access token is invalid', async () => {
    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.userinfo('');

    await assertError(
      promise,
      MonoCloudValidationError,
      'Access token is required for fetching userinfo'
    );
  });

  it.each([
    {
      error: 'some_unknown_error',
      error_description: 'Some unknwon error occured',
    },
    { error: null, error_description: null },
  ])(
    'should give a failure response 401 when there is an authentication error',
    async e => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureUserinfo({
          responseCode: 401,
          responseHeaders: {
            'WWW-Authenticate': `Bearer ${e.error ? `error="${e.error}"` : ''}${e.error_description ? `,error_description="${e.error_description}"` : ''}`,
          },
        })
        .createSpy();

      const client = new MonoCloudOidcClient('example.com', 'clientId');

      const promise = client.userinfo('at');

      await assertError(
        promise,
        MonoCloudOPError,
        e.error ?? 'userinfo_failed',
        e.error_description ?? 'Userinfo authentication error'
      );

      fetchSpy.assert();
    }
  );

  it('should return unauthorized if status is 401', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureUserinfo({
        responseCode: 401,
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.userinfo('at');

    await assertError(
      promise,
      MonoCloudHttpError,
      'Error while fetching userinfo. Unexpected status code: 401'
    );

    fetchSpy.assert();
  });

  it('should return a failed result if status code is other than 200', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureUserinfo({
        responseCode: 500,
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.userinfo('at');

    await assertError(
      promise,
      MonoCloudHttpError,
      'Error while fetching userinfo. Unexpected status code: 500'
    );

    fetchSpy.assert();
  });

  it('should return a failed result if server is unreachable', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('fetch failed');
    });

    const client = new MonoCloudOidcClient('example', 'clientId');

    const promise = client.userinfo('at');

    await assertError(promise, MonoCloudHttpError, 'fetch failed');

    fetchSpy.mockClear();
  });
});
