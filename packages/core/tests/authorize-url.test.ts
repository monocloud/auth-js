// eslint-disable-next-line import/no-extraneous-dependencies
import { describe, expect, it } from 'vitest';
import { MonoCloudOidcClient } from '../src/monocloud-oidc-client';
import { fetchBuilder } from '@monocloud/auth-test-utils';

describe('MonoCloudOidcClient.authorizeUrl()', () => {
  it('should generate an authorization url', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const authUrl = await client.authorizationUrl({
      state: 'state',
      scopes: 'scopes openid',
      redirectUri: 'redirectUri',
      responseType: 'code id_token',
      codeChallenge: 'codeChallenge',
      codeChallengeMethod: 'plain',
      authenticatorHint: 'google',
      maxAge: 100,
      loginHint: 'loginHint',
      request: 'request',
      responseMode: 'query',
      acrValues: ['some', 'acr'],
      nonce: 'nonce',
      uiLocales: 'uiLocales',
      display: 'page',
      prompt: 'consent',
      requestUri: 'requestUri',
      resource: 'resource1 resource2',
    });

    expect(authUrl).toBe(
      'https://example.com/connect/authorize?client_id=clientId&redirect_uri=redirectUri&request_uri=requestUri&scope=scopes+openid&response_type=code+id_token&authenticator_hint=google&login_hint=loginHint&request=request&response_mode=query&acr_values=some+acr&nonce=nonce&ui_locales=uiLocales&display=page&max_age=100&prompt=consent&resource=resource1&resource=resource2&code_challenge=codeChallenge&code_challenge_method=plain&state=state'
    );
    fetchSpy.assert();
  });

  it('should set defaults', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const authUrl = await client.authorizationUrl({ codeChallenge: 'test' });

    expect(authUrl).toBe(
      'https://example.com/connect/authorize?client_id=clientId&response_type=code&code_challenge=test&code_challenge_method=S256'
    );
    fetchSpy.assert();
  });

  it('should not set the code challenge if not provided', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const authUrl = await client.authorizationUrl({});

    const query = new URL(authUrl).searchParams;

    const codeChallenge = query.get('code_challenge');
    const codeChallengeMethod = query.get('code_challenge_method');

    expect(codeChallenge).toBeNull();
    expect(codeChallengeMethod).toBeNull();
    fetchSpy.assert();
  });
});
