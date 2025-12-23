/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it } from 'vitest';
import { MonoCloudOidcClient } from '../src';
import { fetchBuilder } from '@monocloud/auth-test-utils';

describe('MonoCloudOidcClient.endsessionUrl()', () => {
  it('should generate an endsession url - 1', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const endSessionUrl = await client.endSessionUrl({
      idToken: 'idtoken',
      postLogoutRedirectUri: 'postLogoutRedirectUri',
      state: 'state',
    });

    expect(endSessionUrl).toBe(
      'https://example.com/connect/endsession?client_id=clientId&id_token_hint=idtoken&post_logout_redirect_uri=postLogoutRedirectUri&state=state'
    );
    fetchSpy.assert();
  });

  it('should generate an endsession url - 2', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const endSessionUrl = await client.endSessionUrl({});

    expect(endSessionUrl).toBe(
      'https://example.com/connect/endsession?client_id=clientId'
    );
    fetchSpy.assert();
  });

  it('should generate an endsession url - 3', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const endSessionUrl = await client.endSessionUrl({
      idToken: 'idtoken',
      postLogoutRedirectUri: 'postLogoutRedirectUri',
    });

    expect(endSessionUrl).toBe(
      'https://example.com/connect/endsession?client_id=clientId&id_token_hint=idtoken&post_logout_redirect_uri=postLogoutRedirectUri'
    );
    fetchSpy.assert();
  });
});
