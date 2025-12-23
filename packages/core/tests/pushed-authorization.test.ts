/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import {
  MonoCloudHttpError,
  MonoCloudOidcClient,
  MonoCloudOPError,
} from '../src';
import { fetchBuilder } from '@monocloud/auth-test-utils';
import { assertError } from './utils';

describe('MonoCloudOidcClient.pushedAuthorizationRequest()', () => {
  it('should perform request at par endpoint', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configurePar({
        body: 'client_id=clientId&redirect_uri=redirectUri&scope=openid+api&response_type=code&authenticator_hint=google&login_hint=username&request=request&response_mode=form_post&acr_values=some&nonce=nonce&ui_locales=locale&display=page&max_age=100&prompt=none&resource=resource1&resource=resource2&code_challenge=challenge&code_challenge_method=S256&state=state',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.pushedAuthorizationRequest({
      acrValues: ['some'],
      authenticatorHint: 'google',
      codeChallenge: 'challenge',
      display: 'page',
      loginHint: 'username',
      maxAge: 100,
      nonce: 'nonce',
      prompt: 'none',
      redirectUri: 'redirectUri',
      request: 'request',
      responseMode: 'form_post',
      responseType: 'code',
      scopes: 'openid api',
      state: 'state',
      uiLocales: 'locale',
      resource: 'resource1 resource2',
    });

    fetchSpy.assert();
    expect(result).toEqual({
      request_uri: 'some uri',
      expires_in: 2000,
    });
  });

  it('should return a failed result if the server is unreachable', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('fetch failed');
    });

    const client = new MonoCloudOidcClient('one', 'clientId');

    const promise = client.pushedAuthorizationRequest({});

    await assertError(promise, MonoCloudHttpError, 'fetch failed');

    fetchSpy.mockClear();
  });

  it.each([
    {
      error: 'request_failed',
      error_description: 'Request failed due to some error',
    },
    { error: null, error_description: null },
  ])('should return a failed result if server returned a 400', async error => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configurePar({
        body: 'client_id=clientId&scope=openid&response_type=code',
        ...error,
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.pushedAuthorizationRequest({ scopes: 'openid' });

    await assertError(
      promise,
      MonoCloudOPError,
      error.error ?? 'par_request_failed',
      error.error_description ?? 'Pushed Authorization Request Failed'
    );

    fetchSpy.assert();
  });

  it('should return a failed result if server returned an unexpected status code', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configurePar({
        responseCode: 500,
        body: 'client_id=clientId&scope=openid&response_type=code',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.pushedAuthorizationRequest({ scopes: 'openid' });

    await assertError(
      promise,
      MonoCloudHttpError,
      'Error while performing pushed authorization request. Unexpected status code: 500'
    );

    fetchSpy.assert();
  });
});
