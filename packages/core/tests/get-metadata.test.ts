/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import { MonoCloudHttpError, MonoCloudOidcClient } from '../src';
import { defaultMetadata, fetchBuilder } from '@monocloud/auth-test-utils';
import { assertError } from './utils';

describe('MonoCloudOidcClient.getMetadata()', () => {
  it('should fetch metadata', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.getMetadata();

    fetchSpy.assert();
    expect(result).toEqual(defaultMetadata);
  });

  it('should throw deserialization error if the response body is invalid', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      return Promise.resolve(
        new Response('{', { headers: { 'content-type': 'application/json' } })
      );
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.getMetadata();

    const nodeMajor = parseInt(process?.versions?.node?.split('.')[0]);

    const errorMessage =
      nodeMajor > 20
        ? "Failed to parse response body as JSON : Expected property name or '}' in JSON at position 1 (line 1 column 2)"
        : "Failed to parse response body as JSON : Expected property name or '}' in JSON at position 1";

    await assertError(promise, MonoCloudHttpError, errorMessage);

    fetchSpy.mockClear();
  });

  it('should return a failed result if server is unreachable', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('fetch failed');
    });

    const client = new MonoCloudOidcClient('server', 'clientId');

    const promise = client.getMetadata();

    await assertError(promise, MonoCloudHttpError, 'fetch failed');

    fetchSpy.mockClear();
  });

  it('should return a failed result if status code is other than 200', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata({ responseCode: 201 })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.getMetadata();

    await assertError(
      promise,
      MonoCloudHttpError,
      'Error while fetching metadata. Unexpected status code: 201'
    );

    fetchSpy.assert();
  });

  it('should fetch from the cache', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const dateSpy = vi.spyOn(Date, 'now').mockReturnValue(10_000);

    const client = new MonoCloudOidcClient('example.com', 'clientId', {
      metadataCacheDuration: 10,
    });

    const result = await client.getMetadata();

    dateSpy.mockReturnValue(10_000 + 9 * 1000);

    const result2 = await client.getMetadata();

    dateSpy.mockClear();

    fetchSpy.assert();
    expect(result).toEqual(result2);
  });

  it('should fetch from the server when cache expires', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureMetadata({ metadata: {} })
      .createSpy();

    const dateSpy = vi.spyOn(Date, 'now').mockReturnValue(10_000);

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.getMetadata();

    dateSpy.mockReturnValue(10_000 + 301 * 1000);

    const result2 = await client.getMetadata();

    dateSpy.mockClear();

    fetchSpy.assert();
    expect(result).toEqual(defaultMetadata);
    expect(result2).toEqual({});
  });

  it('should keep the cached metadata when a forced refresh fails', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementationOnce(() =>
        Promise.resolve(
          new Response(JSON.stringify(defaultMetadata), {
            headers: { 'content-type': 'application/json' },
          })
        )
      )
      .mockImplementationOnce(() =>
        Promise.resolve(new Response('', { status: 500 }))
      );

    const dateSpy = vi.spyOn(Date, 'now').mockReturnValue(10_000);

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.getMetadata();
    expect(result).toEqual(defaultMetadata);

    await assertError(
      client.getMetadata(true),
      MonoCloudHttpError,
      'Error while fetching metadata. Unexpected status code: 500'
    );

    const result2 = await client.getMetadata();

    expect(result2).toEqual(defaultMetadata);
    expect(fetchSpy).toHaveBeenCalledTimes(2);

    dateSpy.mockClear();
    fetchSpy.mockRestore();
  });

  it('should use metadataResolver instead of fetching the discovery document', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('discovery should not be fetched');
    });

    const custom = { ...defaultMetadata, issuer: 'https://custom.example.com' };

    const client = new MonoCloudOidcClient('example.com', 'clientId', {
      metadataResolver: (): typeof custom => custom,
    });

    const result = await client.getMetadata();

    expect(result).toEqual(custom);
    expect(fetchSpy).not.toHaveBeenCalled();

    fetchSpy.mockClear();
  });

  it('should cache metadata returned by metadataResolver', async () => {
    let resolverCalls = 0;
    const resolver = (): typeof defaultMetadata => {
      resolverCalls += 1;
      return defaultMetadata;
    };
    const dateSpy = vi.spyOn(Date, 'now').mockReturnValue(10_000);

    const client = new MonoCloudOidcClient('example.com', 'clientId', {
      metadataResolver: resolver,
      metadataCacheDuration: 10,
    });

    await client.getMetadata();

    dateSpy.mockReturnValue(10_000 + 9 * 1000);

    await client.getMetadata();

    expect(resolverCalls).toBe(1);

    dateSpy.mockClear();
  });
});
