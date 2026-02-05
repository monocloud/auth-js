/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-param-reassign */
/* eslint-disable @typescript-eslint/no-non-null-assertion */

import nock from 'nock';
import { afterEach, describe, expect, it } from 'vitest';
import type { MonoCloudSession, MonoCloudUser } from '@monocloud/auth-core';
import { MonoCloudValidationError } from '@monocloud/auth-core';
import { decrypt, encrypt } from '@monocloud/auth-core/utils';
import { now } from '@monocloud/auth-core/internal';
import { getOptions } from '../src/options/get-options';
import { MonoCloudOptions, SessionLifetime } from '../src/types';
import { MonoCloudCoreClient } from '../src';
import {
  createTestIdToken,
  defaultConfig,
  defaultStoreKeyForTest,
  TestReq,
  TestRes,
} from './test-helpers';
import { freeze, travel } from 'timekeeper';
import { defaultMetadata } from '@monocloud/auth-test-utils';

const testConfig = defaultConfig as Required<MonoCloudOptions>;

const getConfiguredInstance = (
  options: Partial<MonoCloudOptions> = {}
): MonoCloudCoreClient => {
  return new MonoCloudCoreClient(getOptions({ ...defaultConfig, ...options }));
};

const setSessionCookieValue = async (
  cookies: any,
  value: {
    session?: Partial<MonoCloudSession>;
    lifetime?: Partial<SessionLifetime>;
  }
): Promise<void> => {
  cookies.session = {
    value: await encrypt(
      JSON.stringify({
        key: defaultStoreKeyForTest,
        session: value.session,
        lifetime: value.lifetime,
      }),
      testConfig.cookieSecret
    ),
  };
};

const assertSessionCookieValue = async (
  cookies: any,
  assert?: { session?: Record<string, any>; lifetime?: Record<string, any> },
  secret?: string
): Promise<void> => {
  let cookieValue;

  if (Object.keys(cookies).filter(x => x.startsWith('session')).length > 1) {
    cookieValue = Object.entries(cookies)
      .map(([key, value]) => ({
        key: parseInt(key.split('.').pop() ?? '0', 10),
        value,
      }))
      .sort((a, b) => a.key - b.key)
      .map(({ value }: any) => value.value)
      .join('');
  } else {
    cookieValue = cookies.session.value;
  }

  const cookie = JSON.parse(
    (await decrypt(cookieValue, secret ?? testConfig.cookieSecret))!
  );

  expect(cookie.key.length).toBeGreaterThan(0);

  if (assert?.lifetime) {
    expect(cookie.lifetime).toEqual(assert.lifetime);
  }

  if (assert?.session) {
    expect(cookie.session).toEqual(assert.session);
  }
};

describe('MonoCloud Base Instance', () => {
  afterEach(nock.cleanAll);

  describe('getTokens()', () => {
    it('should throw an error if options validation fails', async () => {
      const instance = getConfiguredInstance();

      try {
        await instance.getTokens(new TestReq(), new TestRes(), {
          forceRefresh: 'invalid' as unknown as boolean,
        });
        throw new Error();
      } catch (error) {
        expect(error).toBeInstanceOf(MonoCloudValidationError);
        expect((error as Error).message).toBe(
          '"forceRefresh" must be a boolean'
        );
      }
    });

    it('should be able to customize if the session using onSessionCreating', async () => {
      const frozenTimeMs = 1330688329321;
      freeze(frozenTimeMs);

      const createdIdToken = await createTestIdToken({
        username: 'oooooooooosername',
      });

      nock('https://example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, defaultMetadata);

      nock('https://example.com')
        .matchHeader(
          'authorization',
          'Basic X190ZXN0X2NsaWVudF9pZF9fOl9fdGVzdF9jbGllbnRfc2VjcmV0X18='
        )
        .post('/connect/token', body => {
          expect(body).toEqual({
            grant_type: 'refresh_token',
            refresh_token: 'rt',
          });
          return true;
        })
        .reply(200, {
          access_token: 'at1',
          refresh_token: 'rt1',
          id_token: createdIdToken.idToken,
          scope: 'openid something',
          token_type: 'Bearer',
          expires_in: 999,
        });

      nock('https://example.com')
        .get('/.well-known/openid-configuration/jwks')
        .reply(200, { keys: [createdIdToken.key] });

      const cookies = {};

      const oldTime = now();
      await setSessionCookieValue(cookies, {
        session: {
          user: { sub: createdIdToken.sub },
          accessTokens: [
            {
              scopes: 'openid abc',
              accessToken: 'at',
              accessTokenExpiration: oldTime + 100,
            },
          ],
          idToken: 'idtoken',
          refreshToken: 'rt',
        },
        lifetime: { u: oldTime, e: oldTime + 86400, c: oldTime },
      });

      const req = new TestReq({ cookies });
      const res = new TestRes(cookies);

      const instance = getConfiguredInstance({
        onSessionCreating: (session, idtoken, userinfo, appState) => {
          expect(appState).toBeUndefined();
          expect(userinfo).toBeUndefined();
          expect(idtoken).toBeDefined();
          session.custom = 1;
        },
        idTokenSigningAlg: 'ES256',
        refetchUserInfo: false,
        userInfo: false,
      });

      const newFrozenTime = frozenTimeMs + 2000;
      travel(newFrozenTime);

      const tokens = await instance.getTokens(req, res, {
        forceRefresh: true,
      });

      expect(tokens).toEqual({
        accessToken: 'at1',
        scopes: 'openid something',
        accessTokenExpiration: expect.any(Number),
        idToken: createdIdToken.idToken,
        refreshToken: 'rt1',
        isExpired: false,
      });

      await assertSessionCookieValue(cookies, {
        session: {
          user: {
            sub_jwk: createdIdToken.key,
            sub: createdIdToken.sub,
            username: 'oooooooooosername',
          },
          accessTokens: [
            {
              accessToken: 'at1',
              scopes: 'openid something',
              accessTokenExpiration: expect.any(Number),
            },
          ],
          idToken: createdIdToken.idToken,
          refreshToken: 'rt1',
          custom: 1,
        },
        lifetime: { c: oldTime, e: oldTime + 86400, u: now() },
      });
    });

    it('should throw if session is not found', async () => {
      const cookies = {};

      await setSessionCookieValue(cookies, {
        lifetime: { u: now(), e: now() + 86400, c: now() },
      });

      const req = new TestReq({ cookies });
      const res = new TestRes(cookies);

      const instance = getConfiguredInstance();

      try {
        await instance.getTokens(req, res);
      } catch (error) {
        expect(error).toBeInstanceOf(MonoCloudValidationError);
        expect((error as any).message).toBe('Session does not exist');
      }
    });

    it('should throw error if refresh grant fails', async () => {
      nock('https://example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, defaultMetadata);

      nock('https://example.com').post('/connect/token').reply(400, {
        error: 'error',
        error_description: 'errorDescription',
      });

      const cookies = {};

      await setSessionCookieValue(cookies, {
        session: {
          user: { sub: 'sub' },
          scopes: 'abc',
          accessToken: 'at',
          accessTokenExpiration: now() + 100,
          idToken: 'idtoken',
          refreshToken: 'rt',
        },
        lifetime: { u: now(), e: now() + 86400, c: now() },
      });

      const req = new TestReq({ cookies });
      const res = new TestRes(cookies);

      const instance = getConfiguredInstance({ idTokenSigningAlg: 'ES256' });

      await expect(() =>
        instance.getTokens(req, res, {
          forceRefresh: true,
        })
      ).rejects.toThrow('error');
    });

    it('should throw error if userinfo fails', async () => {
      nock('https://example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, defaultMetadata);

      nock('https://example.com')
        .matchHeader(
          'authorization',
          'Basic X190ZXN0X2NsaWVudF9pZF9fOl9fdGVzdF9jbGllbnRfc2VjcmV0X18='
        )
        .post('/connect/token', body => {
          expect(body).toEqual({
            grant_type: 'refresh_token',
            refresh_token: 'rt',
          });
          return true;
        })
        .reply(200, {
          access_token: 'at1',
          id_token: 'idtoken',
          refresh_token: 'rt1',
          scope: 'openid something',
          token_type: 'Bearer',
          expires_in: 999,
        });

      nock('https://example.com').get('/connect/userinfo').reply(400, {
        error: 'error',
        error_description: 'errorDescription',
      });

      const cookies = {};

      await setSessionCookieValue(cookies, {
        session: {
          user: { sub: 'sub' },
          accessTokens: [
            {
              scopes: 'openid abc',
              accessToken: 'at',
              accessTokenExpiration: now() + 100,
            },
          ],
          idToken: 'idtoken',
          refreshToken: 'rt',
        },
        lifetime: { u: now(), e: now() + 86400, c: now() },
      });

      const req = new TestReq({ cookies });
      const res = new TestRes(cookies);

      const instance = getConfiguredInstance({
        refetchUserInfo: true,
      });

      await expect(() =>
        instance.getTokens(req, res, {
          forceRefresh: true,
        })
      ).rejects.toThrow(
        'Error while fetching userinfo. Unexpected status code: 400'
      );
    });

    it('should throw error if jwks fetch fails', async () => {
      nock('https://example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, defaultMetadata);

      nock('https://example.com')
        .matchHeader(
          'authorization',
          'Basic X190ZXN0X2NsaWVudF9pZF9fOl9fdGVzdF9jbGllbnRfc2VjcmV0X18='
        )
        .post('/connect/token', body => {
          expect(body).toEqual({
            grant_type: 'refresh_token',
            refresh_token: 'rt',
          });
          return true;
        })
        .reply(200, {
          access_token: 'at1',
          id_token: 'idtoken',
          refresh_token: 'rt1',
          scope: 'openid something',
          token_type: 'Bearer',
          expires_in: 999,
        });

      nock('https://example.com')
        .get('/.well-known/openid-configuration/jwks')
        .reply(400);

      const cookies = {};

      await setSessionCookieValue(cookies, {
        session: {
          user: { sub: 'sub' },
          scopes: 'abc',
          accessToken: 'at',
          accessTokenExpiration: now() + 100,
          idToken: 'idtoken',
          refreshToken: 'rt',
        },
        lifetime: { u: now(), e: now() + 86400, c: now() },
      });

      const req = new TestReq({ cookies });
      const res = new TestRes(cookies);

      const instance = getConfiguredInstance({
        refetchUserInfo: false,
      });

      await expect(() =>
        instance.getTokens(req, res, {
          forceRefresh: true,
        })
      ).rejects.toThrow(
        'Error while fetching JWKS. Unexpected status code: 400'
      );
    });

    it('should throw error if id token validation fails', async () => {
      const createdIdToken = await createTestIdToken({
        username: 'oooooooooosername',
      });
      nock('https://example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, defaultMetadata);

      nock('https://example.com')
        .matchHeader(
          'authorization',
          'Basic X190ZXN0X2NsaWVudF9pZF9fOl9fdGVzdF9jbGllbnRfc2VjcmV0X18='
        )
        .post('/connect/token', body => {
          expect(body).toEqual({
            grant_type: 'refresh_token',
            refresh_token: 'rt',
          });
          return true;
        })
        .reply(200, {
          access_token: 'at1',
          id_token: 'idtoken',
          refresh_token: 'rt1',
          scope: 'openid something',
          token_type: 'Bearer',
          expires_in: 999,
        });

      nock('https://example.com')
        .get('/.well-known/openid-configuration/jwks')
        .reply(200, { keys: [createdIdToken.key] });

      const cookies = {};

      await setSessionCookieValue(cookies, {
        session: {
          user: { sub: createdIdToken.sub },
          scopes: 'abc',
          accessToken: 'at',
          accessTokenExpiration: now() + 100,
          idToken: 'idtoken',
          refreshToken: 'rt',
        },
        lifetime: { u: now(), e: now() + 86400, c: now() },
      });

      const req = new TestReq({ cookies });
      const res = new TestRes(cookies);

      const instance = getConfiguredInstance({
        idTokenSigningAlg: 'ES256',
        refetchUserInfo: false,
      });

      await expect(() =>
        instance.getTokens(req, res, {
          forceRefresh: true,
        })
      ).rejects.toThrow('ID Token must have a header, payload and signature');
    });
  });
});
