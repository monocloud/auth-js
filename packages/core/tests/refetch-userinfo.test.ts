/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it } from 'vitest';
import { MonoCloudOidcClient } from '../src/monocloud-oidc-client';
import { fetchBuilder } from '@monocloud/auth-test-utils';
import { assertError } from './utils';
import { MonoCloudOPError, MonoCloudValidationError } from '../src';

describe('MonoCloudOidcClient.refetchUserInfo()', () => {
  it('should refetch the userinfo', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureUserinfo({ claims: { sub: 'subject', name: 'user' } })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.refetchUserInfo(
      {
        accessToken: 'at',
        scopes: 'openid',
        accessTokenExpiration: 9999999999,
      },
      {
        user: {
          sub: 'subject',
        },
        accessTokens: [
          {
            accessToken: 'at',
            scopes: 'openid',
            accessTokenExpiration: 9999999999,
          },
        ],
      }
    );

    fetchSpy.assert();
    expect(result).toEqual({
      user: {
        sub: 'subject',
        name: 'user',
      },
      accessTokens: [
        {
          accessToken: 'at',
          scopes: 'openid',
          accessTokenExpiration: 9999999999,
        },
      ],
    });
  });

  it('should give a failed response when the session does not contain scope openid', async () => {
    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.refetchUserInfo(
      {
        accessToken: 'at',
        scopes: 'profile',
        accessTokenExpiration: 9999999999,
      },
      {
        user: {
          sub: 'subject_id',
        },
        accessTokens: [
          {
            accessToken: 'at',
            scopes: 'profile',
            accessTokenExpiration: 9999999999,
          },
        ],
      }
    );

    await assertError(
      promise,
      MonoCloudValidationError,
      'Fetching userinfo requires the openid scope'
    );
  });

  it('should give failed response if there is a authentication failure', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureUserinfo({
        responseCode: 401,
        responseHeaders: {
          'WWW-Authenticate': `Bearer error="token_failed", error_description="The token is expired or invalid"`,
        },
      })
      .createSpy();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.refetchUserInfo(
      {
        accessToken: 'at',
        scopes: 'openid',
        accessTokenExpiration: 9999999999,
      },
      {
        user: {
          sub: 'subject_id',
        },
        accessTokens: [
          {
            accessToken: 'at',
            scopes: 'openid',
            accessTokenExpiration: 9999999999,
          },
        ],
      }
    );

    await assertError(
      promise,
      MonoCloudOPError,
      'token_failed',
      'The token is expired or invalid'
    );

    fetchSpy.assert();
  });

  it('should give a failure result if there is no access token in the session', async () => {
    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.refetchUserInfo(
      {
        accessToken: '',
        scopes: 'openid',
        accessTokenExpiration: 9999999999,
      },
      {
        user: {
          sub: 'subject_id',
        },
        accessTokens: [
          {
            accessToken: '',
            scopes: 'openid',
            accessTokenExpiration: 9999999999,
          },
        ],
      }
    );

    await assertError(
      promise,
      MonoCloudValidationError,
      'Access token is required for fetching userinfo'
    );
  });
});
