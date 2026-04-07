/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import { MonoCloudApiHttpError, MonoCloudApiClient } from '../src';
import { defaultMetadata, fetchBuilder } from '@monocloud/auth-test-utils';
import { assertError, defaultOptions } from './utils';

describe('MonoCloudApiClient.getMetadata()', () => {
  it('should fetch metadata', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const client = new MonoCloudApiClient(
      'example.com',
      'clientId',
      defaultOptions
    );

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

    const client = new MonoCloudApiClient(
      'example.com',
      'clientId',
      defaultOptions
    );

    const promise = client.getMetadata();

    const nodeMajor = parseInt(process?.versions?.node?.split('.')[0]);

    const errorMessage =
      nodeMajor > 20
        ? "Failed to parse response body as JSON : Expected property name or '}' in JSON at position 1 (line 1 column 2)"
        : "Failed to parse response body as JSON : Expected property name or '}' in JSON at position 1";

    await assertError(promise, MonoCloudApiHttpError, errorMessage);

    fetchSpy.mockClear();
  });

  it('should return a failed result if server is unreachable', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('fetch failed');
    });

    const client = new MonoCloudApiClient('server', 'clientId', defaultOptions);

    const promise = client.getMetadata();

    await assertError(promise, MonoCloudApiHttpError, 'fetch failed');

    fetchSpy.mockClear();
  });

  it('should return a failed result if status code is other than 200', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata({ responseCode: 201 })
      .createSpy();

    const client = new MonoCloudApiClient(
      'example.com',
      'clientId',
      defaultOptions
    );

    const promise = client.getMetadata();

    await assertError(
      promise,
      MonoCloudApiHttpError,
      'Error while fetching metadata. Unexpected status code: 201'
    );

    fetchSpy.assert();
  });

  it('should fetch from the cache', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const dateSpy = vi.spyOn(Date, 'now').mockReturnValue(10_000);

    const client = new MonoCloudApiClient('example.com', 'clientId', {
      ...defaultOptions,
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

    const client = new MonoCloudApiClient(
      'example.com',
      'clientId',
      defaultOptions
    );

    const result = await client.getMetadata();

    dateSpy.mockReturnValue(10_000 + 301 * 1000);

    const result2 = await client.getMetadata();

    dateSpy.mockClear();

    fetchSpy.assert();
    expect(result).toEqual(defaultMetadata);
    expect(result2).toEqual({});
  });
});
