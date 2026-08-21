/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import {
  MonoCloudHttpError,
  MonoCloudOidcBackendClient,
  MonoCloudOidcClient,
} from '../src';
import { defaultMetadata, fetchBuilder } from '@monocloud/auth-test-utils';
import { assertError } from './utils';

const TIMEOUT = 20;

const jsonResponse = (body: unknown): Response =>
  new Response(JSON.stringify(body), {
    headers: { 'content-type': 'application/json' },
  });

const metadataUrl = 'https://example.com/.well-known/openid-configuration';

const hang = (init?: RequestInit): Promise<Response> =>
  new Promise((_resolve, reject) => {
    init?.signal?.addEventListener('abort', () =>
      reject(new Error('This operation was aborted'))
    );
  });

const delayedResponse = (init?: RequestInit): Promise<Response> =>
  new Promise((resolve, reject) => {
    init?.signal?.addEventListener('abort', () =>
      reject(new Error('This operation was aborted'))
    );

    setTimeout(() => resolve(jsonResponse(defaultMetadata)), TIMEOUT);
  });

const wait = (ms: number): Promise<void> =>
  new Promise(resolve => {
    setTimeout(resolve, ms);
  });

describe('responseTimeout', () => {
  it('should abort the request and throw once the timeout elapses', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation((_input, init) => hang(init));

    const client = new MonoCloudOidcClient('example.com', 'clientId', {
      responseTimeout: TIMEOUT,
    });

    await assertError(
      client.getMetadata(),
      MonoCloudHttpError,
      `Request to ${metadataUrl} timed out after ${TIMEOUT}ms`
    );

    fetchSpy.mockClear();
  });

  it('should abort a hanging introspection request', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation((input, init) =>
        String(input) === metadataUrl
          ? Promise.resolve(jsonResponse(defaultMetadata))
          : hang(init)
      );

    const client = new MonoCloudOidcBackendClient(
      'example.com',
      'https://api.example.com',
      {
        clientId: 'clientId',
        clientSecret: 'clientSecret',
        responseTimeout: TIMEOUT,
      }
    );

    await assertError(
      client.introspectAccessToken('some-token'),
      MonoCloudHttpError,
      `Request to ${defaultMetadata.introspection_endpoint} timed out after ${TIMEOUT}ms`
    );

    fetchSpy.mockClear();
  });

  it('should surface the original error when the request fails before the timeout', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('fetch failed');
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId', {
      responseTimeout: TIMEOUT,
    });

    await assertError(client.getMetadata(), MonoCloudHttpError, 'fetch failed');

    fetchSpy.mockClear();
  });

  it('should clear the timer once the request completes', async () => {
    let signal: AbortSignal | null | undefined;

    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation((_input, init) => {
        signal = init?.signal;
        return Promise.resolve(jsonResponse(defaultMetadata));
      });

    const client = new MonoCloudOidcClient('example.com', 'clientId', {
      responseTimeout: TIMEOUT,
    });

    expect(await client.getMetadata()).toEqual(defaultMetadata);
    expect(signal).toBeInstanceOf(AbortSignal);

    await wait(TIMEOUT * 2);

    expect(signal?.aborted).toBe(false);

    fetchSpy.mockClear();
  });

  it('should not attach a signal when no timeout is configured', async () => {
    let signal: AbortSignal | null | undefined;

    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation((_input, init) => {
        signal = init?.signal;
        return Promise.resolve(jsonResponse(defaultMetadata));
      });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    expect(await client.getMetadata()).toEqual(defaultMetadata);
    expect(signal).toBeUndefined();

    fetchSpy.mockClear();
  });

  it.each([0, -1])(
    'should not apply a timeout when the configured value is %i',
    async responseTimeout => {
      let signal: AbortSignal | null | undefined;

      const fetchSpy = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation((_input, init) => {
          signal = init?.signal;
          return delayedResponse(init);
        });

      const client = new MonoCloudOidcClient('example.com', 'clientId', {
        responseTimeout,
      });

      expect(await client.getMetadata()).toEqual(defaultMetadata);
      expect(signal).toBeUndefined();

      fetchSpy.mockClear();
    }
  );

  it('should preserve the request init alongside the abort signal', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureRefreshToken({
        body: 'grant_type=refresh_token&refresh_token=rt',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId', {
      responseTimeout: TIMEOUT,
    });

    const result = await client.refreshGrant('rt');

    fetchSpy.assert();
    expect(result.access_token).toBe('at');
  });
});
