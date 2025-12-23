/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import {
  MonoCloudHttpError,
  MonoCloudOidcClient,
  MonoCloudValidationError,
  Jwks,
} from '../src';
import { defaultMetadata, fetchBuilder } from '@monocloud/auth-test-utils';
import { assertError } from './utils';

const jwks: Jwks = {
  keys: [
    {
      kid: 'id',
      kty: 'RSA',
      use: 'sig',
      x5t: 'thumbprint',
      e: 'AQAB',
      n: 'num',
      alg: 'RS256',
    },
  ],
};

describe('MonoCloudOidcClient.getJwks()', () => {
  it('should fetch jwks', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks({ jwks })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.getJwks();

    fetchSpy.assert();
    expect(result).toEqual(jwks);
  });

  it('should return a failed result if server is unreachable', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('fetch failed');
    });

    const client = new MonoCloudOidcClient('server', 'clientId');

    const promise = client.getJwks();

    await assertError(promise, MonoCloudHttpError, 'fetch failed');

    fetchSpy.mockClear();
  });

  it('should return a failed result if status code is other than 200', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks({ responseCode: 201 })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.getJwks();

    await assertError(
      promise,
      MonoCloudHttpError,
      'Error while fetching JWKS. Unexpected status code: 201'
    );

    fetchSpy.assert();
  });

  it('should fetch from cache', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks({ jwks })
      .createSpy();

    const dateSpy = vi.spyOn(Date, 'now').mockReturnValue(10_000);

    const client = new MonoCloudOidcClient('example.com', 'clientId', {
      jwksCacheDuration: 10,
    });

    const result = await client.getJwks();

    dateSpy.mockReturnValue(10_000 + 9 * 1000);

    const result2 = await client.getJwks();

    dateSpy.mockClear();

    expect(result).toEqual(result2);

    fetchSpy.assert();
  });

  it('should fetch from the server when cache expires', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureMetadata()
      .configureJwks({ jwks })
      .configureJwks({ jwks: { keys: [] } })
      .createSpy();

    const dateSpy = vi.spyOn(Date, 'now').mockReturnValue(10_000);

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.getJwks();

    dateSpy.mockReturnValue(10_000 + 61 * 1000);

    const result2 = await client.getJwks();

    dateSpy.mockClear();

    fetchSpy.assert();
    expect(result).toEqual(jwks);
    expect(result2).toEqual({
      keys: [],
    });
  });

  it('should throw an error if the jwks endpoint is not found in the metadata', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata({
        metadata: { ...defaultMetadata, jwks_uri: undefined },
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.getJwks();

    await assertError(
      promise,
      MonoCloudValidationError,
      'jwks_uri endpoint is required but not available in the issuer metadata'
    );

    fetchSpy.assert();
  });
});
