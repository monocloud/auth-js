/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import {
  MonoCloudHttpError,
  MonoCloudOidcClient,
  MonoCloudOPError,
} from '../src';
import { fetchBuilder, mtlsFetchSpy } from '@monocloud/auth-test-utils';
import { assertError } from './utils';

describe('MonoCloudOidcClient.pushedAuthorizationRequest()', () => {
  it('should perform request at par endpoint', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configurePar({
        body: 'client_id=clientId&redirect_uri=redirectUri&scope=openid+api&response_type=code&authenticator_hint=google&login_hint=username&request=request&response_mode=form_post&acr_values=some&nonce=nonce&ui_locales=locale&display=page&max_age=100&prompt=none&audience=audience&id_token_hint=idTokenHint&resource=resource1&resource=resource2&code_challenge=challenge&code_challenge_method=S256&state=state',
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
      audience: 'audience',
      idTokenHint: 'idTokenHint',
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

  it('should surface the oauth error when the server returns a 401', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configurePar({
        body: 'client_id=clientId&scope=openid&response_type=code',
        responseCode: 401,
        error: 'invalid_client',
        error_description: 'Client authentication failed',
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    await assertError(
      client.pushedAuthorizationRequest({ scopes: 'openid' }),
      MonoCloudOPError,
      'invalid_client',
      'Client authentication failed'
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

  it('should perform PAR at the mTLS endpoint alias for mTLS auth methods', async () => {
    const fetchSpy = mtlsFetchSpy({
      response: { request_uri: 'some uri', expires_in: 2000 },
      responseCode: 201,
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId', {
      clientAuthMethod: 'tls_client_auth',
    });

    await client.pushedAuthorizationRequest({ scopes: 'openid' });

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://mtls.example.com/connect/par',
      expect.objectContaining({ method: 'POST' })
    );

    fetchSpy.mockClear();
  });
});
