/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-param-reassign */
/* eslint-disable @typescript-eslint/no-non-null-assertion */

import nock from 'nock';
import * as jose from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  IssuerMetadata,
  MonoCloudSession,
  MonoCloudUser,
} from '@monocloud/auth-core';
import {
  MonoCloudOPError,
  MonoCloudValidationError,
} from '@monocloud/auth-core';
import { decrypt, encrypt } from '@monocloud/auth-core/utils';
import { now } from '@monocloud/auth-core/internal';
import { getOptions } from '../src/options/get-options';
import {
  MonoCloudOptions,
  MonoCloudState,
  SessionLifetime,
} from '../src/types';
import { MonoCloudCoreClient } from '../src';
import {
  createTestIdToken,
  defaultConfig,
  defaultSessionData,
  defaultStoreKeyForTest,
  getSessionCookie,
  TestReq,
  TestRes,
} from './test-helpers';
import { freeze, reset, travel } from 'timekeeper';
import { defaultMetadata } from '@monocloud/auth-test-utils';

const testConfig = defaultConfig as Required<MonoCloudOptions>;

const setupDiscovery = (discoveryDoc: Partial<IssuerMetadata> = {}): void => {
  nock(testConfig.tenantDomain)
    .get('/.well-known/openid-configuration')
    .reply(200, { issuer: testConfig.tenantDomain, ...discoveryDoc });
};

const getConfiguredInstance = (
  options: Partial<MonoCloudOptions> = {}
): MonoCloudCoreClient => {
  return new MonoCloudCoreClient(getOptions({ ...defaultConfig, ...options }));
};

const setStateCookieValue = async (
  cookies: any,
  authState?: Partial<MonoCloudState>,
  secret?: string,
  cookieName?: string
): Promise<void> => {
  authState = {
    appState: '{}',
    nonce: '123',
    state: 'peace',
    codeVerifier: 'a', // ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs
    scopes: 'openid profile read:customer',
    ...(authState ?? {}),
  };
  cookies[cookieName ?? 'state'] = {
    value: await encrypt(
      JSON.stringify({ authState }),
      secret ?? testConfig.cookieSecret
    ),
  };
};

const assertStateCookieValue = async (
  res: TestRes,
  valueCheck: Record<string, any> = {}
): Promise<void> => {
  const cookieValue = res.cookies.state.value;

  const cookie = JSON.parse(
    (await decrypt(cookieValue, testConfig.cookieSecret))!
  ).authState;

  expect(cookie.codeVerifier.length).toBeGreaterThan(0);

  for (const key of Object.keys(valueCheck)) {
    expect(cookie[key]).toEqual(valueCheck[key]);
  }
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

  describe('handlers', () => {
    describe('signin', () => {
      it('should redirect to authorize url', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });

        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://example.com/connect/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(8);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );

        assertStateCookieValue(res, {
          nonce: search.nonce,
          state: search.state,
          returnUrl: encodeURIComponent(testConfig.appUrl),
          appState: '{}',
        });
      });

      it('should set openid as default scope', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });

        const instance = getConfiguredInstance();

        // @ts-expect-error FOR TESTING
        instance.options.defaultAuthParams.scopes = undefined;

        const cookies = {};
        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://example.com/connect/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(8);
        expect(search.scope).toBe('openid');

        assertStateCookieValue(res, {
          nonce: search.nonce,
          state: search.state,
          returnUrl: encodeURIComponent(testConfig.appUrl),
          appState: '{}',
          scopes: 'openid',
        });
      });

      it('should combine all scopes and resources for authorize request', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });

        const instance = getConfiguredInstance({
          defaultAuthParams: {
            ...defaultConfig.defaultAuthParams,
            resource: 'https://default.com',
            scopes: 'openid profile default',
          },
          resources: [
            { resource: 'https://one.com', scopes: 'one' },
            {
              resource: 'https://two.com https://three.com',
              scopes: 'two three',
            },
          ],
        });

        const cookies = {};
        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://example.com/connect/authorize'
        );

        expect(url.searchParams.get('scope')).toBe(
          'openid profile default one two three'
        );
        expect(url.searchParams.getAll('resource')).toEqual([
          'https://default.com',
          'https://one.com',
          'https://two.com',
          'https://three.com',
        ]);

        assertStateCookieValue(res, {
          nonce: url.searchParams.get('nonce'),
          state: url.searchParams.get('state'),
          returnUrl: encodeURIComponent(testConfig.appUrl),
          appState: '{}',
          scopes: 'openid profile default one two three',
        });
      });

      it('should execute custom onError function if provided', async () => {
        const instance = getConfiguredInstance();

        const onError = vi.fn();

        await instance.signIn(null as unknown as TestReq, new TestRes({}), {
          onError,
        });

        expect(onError).toHaveBeenCalledTimes(1);
      });

      it('should have the base path in the redirect uri', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });

        const instance = getConfiguredInstance({
          appUrl: 'https://example.org/basepath',
        });

        const cookies = {};
        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        const url = new URL(res.res.redirectedUrl!);

        const search = Object.fromEntries(url.searchParams.entries());
        expect(search.redirect_uri).toBe(
          'https://example.org/basepath/api/auth/callback'
        );

        assertStateCookieValue(res, {
          nonce: search.nonce,
          state: search.state,
          returnUrl: encodeURIComponent('https://example.org/basepath'),
          appState: '{}',
        });
      });

      it('should be able override auth params except nonce, state, code_challenge + method', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          authParams: {
            state: 'cantchange',
            codeChallenge: 'cannotchange',
            nonce: 'changecant',
            redirectUri: 'testredirect',
            maxAge: 10,
          },
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://example.com/connect/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(9);
        expect(search.state).not.toBe('cantchange');
        expect(search.code_challenge).not.toBe('cannotchange');
        expect(search.nonce).not.toBe('changecant');
        expect(search.code_challenge_method).toBe('S256');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe('testredirect');
        expect(search.max_age).toBe('10');

        assertStateCookieValue(res, {
          nonce: search.nonce,
          state: search.state,
          returnUrl: encodeURIComponent(testConfig.appUrl),
          appState: '{}',
        });
      });

      it('should be able to set login_hint through options', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          authParams: {
            loginHint: 'usernaaaame',
          },
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://example.com/connect/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(9);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.login_hint).toBe('usernaaaame');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
      });

      it('should redirect with prompt=create', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          register: true,
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://example.com/connect/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(9);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.prompt).toBe('create');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
      });

      it('should redirect with authenticator_hint when authenticator is set', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          authParams: {
            authenticatorHint: 'apple',
          },
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://example.com/connect/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(9);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.authenticator_hint).toBe('apple');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
      });

      it('should pick up the auth params from the request even if options are present', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({
          cookies,
          query: {
            authenticator_hint: 'thisshouldbepickedup',
            max_age: '555',
            acr_values: 'sup hello',
            scope: 'openid profile write:customer',
            resource: 'https://api.example.com https://test.example.com',
            display: 'page',
            ui_locales: 'en-IN',
            login_hint: 'email',
            prompt: 'create',
          },
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          authParams: {
            authenticatorHint: 'google',
            maxAge: 123,
            acrValues: ['hello'],
            scopes: 'openid read:customer',
            resource: 'https://api.example.com',
            display: 'popup',
            uiLocales: 'en-US',
            loginHint: 'username',
            prompt: 'consent',
          },
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://example.com/connect/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(16);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.max_age).toBe('555');
        expect(search.acr_values).toBe('sup hello');
        expect(url.searchParams.getAll('resource').join(' ')).toBe(
          'https://api.example.com https://test.example.com'
        );
        expect(search.display).toBe('page');
        expect(search.ui_locales).toBe('en-IN');
        expect(search.login_hint).toBe('email');
        expect(search.prompt).toBe('create');
        expect(search.authenticator_hint).toBe('thisshouldbepickedup');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile write:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
      });

      it('should not pick up the auth params from the request if allowQueryParamOverrides', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance({
          allowQueryParamOverrides: false,
        });

        const cookies = {};
        const req = new TestReq({
          cookies,
          query: {
            authenticator_hint: 'nope',
            max_age: '555',
            acr_values: 'sup hello',
            scope: 'openid profile write:customer',
            resource: 'https://api.example.com https://test.example.com',
            display: 'page',
            ui_locales: 'en-IN',
            login_hint: 'email',
            prompt: 'create',
          },
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          authParams: {
            authenticatorHint: 'google',
            maxAge: 123,
            acrValues: ['hello'],
            scopes: 'new',
            resource: 'https://api.example.com',
            display: 'popup',
            uiLocales: 'en-US',
            loginHint: 'username',
            prompt: 'consent',
          },
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://example.com/connect/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(16);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.max_age).toBe('123');
        expect(search.acr_values).toBe('hello');
        expect(url.searchParams.getAll('resource').join(' ')).toBe(
          'https://api.example.com'
        );
        expect(search.display).toBe('popup');
        expect(search.ui_locales).toBe('en-US');
        expect(search.login_hint).toBe('username');
        expect(search.prompt).toBe('consent');
        expect(search.authenticator_hint).toBe('google');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('new openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
      });

      it('max_age should not be present if the query is not a number', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({
          cookies,
          query: {
            max_age: 'hello',
          },
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(url.searchParams.get('max_age')).toBeNull();
      });

      it('empty scopes should not override the default scopes', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({
          cookies,
          query: {
            scope: '  ',
          },
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(url.searchParams.get('scope')).toBe(
          'openid profile read:customer'
        );
      });

      it('empty resource should not override the default resource', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance({
          defaultAuthParams: { resource: 'https://test.com' },
        });

        const cookies = {};
        const req = new TestReq({
          cookies,
          query: {
            resource: '  ',
          },
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(url.searchParams.get('resource')).toBe('https://test.com');
      });

      it('should pick up the login_hint from the request even if the loginHint is passed through options', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({
          cookies,
          query: { login_hint: 'oooosername' },
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          authParams: {
            loginHint: 'username',
          },
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://example.com/connect/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(9);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.login_hint).toBe('oooosername');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
      });

      it(`should override prompt with the value from the request`, async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({
          cookies,
          query: { prompt: 'create' },
          method: 'GET',
        });
        const res = new TestRes(cookies);
        await instance.signIn(req, res, {
          authParams: {
            prompt: 'consent',
          },
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://example.com/connect/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(9);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.prompt).toBe('create');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
      });

      it(`should set custom app state in state cookie if onSetApplicationState callback is set to Object`, async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance({
          onSetApplicationState: () => ({
            customState: 'something',
          }),
        });

        const cookies = {};
        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        assertStateCookieValue(res, {
          appState: '{"customState":"something"}',
        });
      });

      [1, null, undefined, Symbol('test'), true, []].forEach(x => {
        it(`should return internal server error if onSetApplicationState returns a non object (${Array.isArray(x) ? 'Array' : typeof x})`, async () => {
          setupDiscovery({
            authorization_endpoint: 'https://example.com/connect/authorize',
          });
          const instance = getConfiguredInstance({
            onSetApplicationState: () => x as any,
          });

          const cookies = {};
          const req = new TestReq({ cookies, method: 'GET' });
          const res = new TestRes(cookies);

          await instance.signIn(req, res);

          expect(res.res.statusCode).toBe(500);
        });
      });

      [
        'code token' as any,
        'code id_token',
        'code id_token token',
        'token',
      ].forEach((responseType, i) => {
        it(`should return internal server error if response type from options is unsupported ${i + 1} of 4`, async () => {
          setupDiscovery({
            authorization_endpoint: 'https://example.com/connect/authorize',
          });
          const instance = getConfiguredInstance();

          const cookies = {};
          const req = new TestReq({ cookies, method: 'GET' });
          const res = new TestRes(cookies);

          await instance.signIn(req, res, {
            authParams: { responseType },
          });

          expect(res.res.statusCode).toBe(500);
        });
      });

      it('should use par if usePar is true', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        nock('https://example.com')
          .matchHeader(
            'authorization',
            'Basic X190ZXN0X2NsaWVudF9pZF9fOl9fdGVzdF9jbGllbnRfc2VjcmV0X18='
          )
          .post('/connect/par', body => {
            const b = new URLSearchParams(body);
            expect(b.size).toBe(8);
            expect(b.get('state')?.length).toBeGreaterThan(0);
            expect(b.get('code_challenge')?.length).toBeGreaterThan(0);
            expect(b.get('nonce')?.length).toBeGreaterThan(0);
            expect(b.get('code_challenge_method')).toBe('S256');
            expect(b.get('client_id')).toBe('__test_client_id__');
            expect(b.get('response_type')).toBe('code');
            expect(b.get('scope')).toBe('openid profile read:customer');
            expect(b.get('redirect_uri')).toBe(
              'https://example.org/api/auth/callback'
            );
            return true;
          })
          .reply(201, {
            request_uri: 'urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2',
            expires_in: 90,
          });

        const instance = getConfiguredInstance({ usePar: true });

        const cookies = {};
        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://example.com/connect/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(2);
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.request_uri).toBe(
          'urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2'
        );
      });

      it('should throw error if par request was a failure', async () => {
        nock('https://example.com').post('/connect/par').reply(400, {
          error: 'oops',
          error_description: 'something went wrong',
        });

        const instance = getConfiguredInstance({ usePar: true });

        const cookies = {};
        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        expect(res.res.statusCode).toBe(500);
      });

      it('can pass custom return_url for application redirects', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          returnUrl: '/custom',
        });

        assertStateCookieValue(res, {
          returnUrl: encodeURIComponent('/custom'),
        });
      });

      it.each(['/custom', 'https://example.org/custom'])(
        'can pass custom application return url through request query',
        async return_url => {
          setupDiscovery({
            authorization_endpoint: 'https://example.com/connect/authorize',
          });
          const instance = getConfiguredInstance();

          const cookies = {};
          const req = new TestReq({
            cookies,
            query: { return_url },
            method: 'GET',
          });
          const res = new TestRes(cookies);

          await instance.signIn(req, res);

          assertStateCookieValue(res, {
            returnUrl: encodeURIComponent(return_url),
          });
        }
      );

      it('should set same site to none if the response_mode is form_post', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://example.com/connect/authorize',
        });
        const instance = getConfiguredInstance({
          defaultAuthParams: { responseMode: 'form_post' },
        });

        const cookies = {} as any;
        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        expect(cookies.state.options.sameSite).toBe('none');
      });

      ['DELETE', 'PUT', 'POST', 'PATCH', 'OPTIONS', 'TRACE', 'HEAD'].forEach(
        (method: any) => {
          it('should return method not allowed for unsupported methods', async () => {
            setupDiscovery({
              authorization_endpoint: 'https://example.com/connect/authorize',
            });
            const instance = getConfiguredInstance({
              defaultAuthParams: { responseMode: 'form_post' },
            });

            const cookies = {} as any;
            const req = new TestReq({
              cookies,
              method,
            });
            const res = new TestRes(cookies);

            await instance.signIn(req, res);

            expect(res.res.statusCode).toBe(405);
          });
        }
      );
    });

    describe('callback', () => {
      let createdIdToken: {
        idToken: string;
        key: jose.JWK;
        sub: string;
      };

      const frozenTimeMs = 1330688329321;

      beforeEach(async () => {
        freeze(frozenTimeMs);

        createdIdToken = await createTestIdToken({
          username: 'oooooooooosername',
          nonce: '123',
        });

        nock('https://example.com')
          .get('/.well-known/openid-configuration/jwks')
          .reply(200, { keys: [createdIdToken.key] });

        nock('https://example.com')
          .matchHeader('authorization', 'Bearer at')
          .get('/connect/userinfo')
          .reply(200, {
            sub: createdIdToken.sub,
            username: 'oooooooooosername',
            test: '123',
          });
      });

      const setupTokenEndpoint = (
        requestBodyCheck: any = {},
        responseBody: any = {
          access_token: 'at',
          id_token: createdIdToken.idToken,
          refresh_token: 'rt',
          scope: 'openid something',
          token_type: 'Bearer',
          expires_in: 999,
        }
      ): void => {
        requestBodyCheck = {
          code: 'code',
          code_verifier: 'a',
          grant_type: 'authorization_code',
          redirect_uri: 'https://example.org/api/auth/callback',
          ...requestBodyCheck,
        };

        nock('https://example.com')
          .matchHeader(
            'authorization',
            'Basic X190ZXN0X2NsaWVudF9pZF9fOl9fdGVzdF9jbGllbnRfc2VjcmV0X18='
          )
          .post('/connect/token', body => {
            expect(body).toEqual(requestBodyCheck);
            return true;
          })
          .reply(200, responseBody);
      };

      afterEach(() => {
        reset();
        createdIdToken = undefined as any;
      });

      ['https://example.com/auth/api/callback', '/auth/api/callback'].forEach(
        url => {
          it('should perform a successful callback (Query)', async () => {
            nock('https://example.com')
              .get('/.well-known/openid-configuration')
              .reply(200, defaultMetadata);

            setupTokenEndpoint();

            const cookies = {} as any;

            await setStateCookieValue(cookies);

            const instance = getConfiguredInstance({
              idTokenSigningAlg: 'ES256',
            });

            const req = new TestReq({
              cookies,
              url: `${url}?state=peace&code=code`,
              method: 'GET',
            });
            const res = new TestRes(cookies);

            await instance.callback(req, res);

            expect(res.res.redirectedUrl).toBe('https://example.org');
            expect(cookies.state).toEqual({
              value: '',
              options: {
                domain: undefined,
                expires: new Date(0),
                httpOnly: true,
                path: '/',
                sameSite: 'lax',
                secure: true,
              },
            });
          });

          it('should perform a successful callback (Body)', async () => {
            nock('https://example.com')
              .get('/.well-known/openid-configuration')
              .reply(200, defaultMetadata);

            setupTokenEndpoint();

            const cookies = {} as any;

            await setStateCookieValue(cookies);

            const instance = getConfiguredInstance({
              idTokenSigningAlg: 'ES256',
            });

            const req = new TestReq({
              cookies,
              url,
              method: 'POST',
              body: { state: 'peace', code: 'code' },
            });
            const res = new TestRes(cookies);

            await instance.callback(req, res);

            expect(res.res.redirectedUrl).toBe('https://example.org');
            expect(cookies.state).toEqual({
              value: '',
              options: {
                domain: undefined,
                expires: new Date(0),
                httpOnly: true,
                path: '/',
                sameSite: 'lax',
                secure: true,
              },
            });
          });
        }
      );

      it('should perform a successful callback (with base path)', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        setupTokenEndpoint({
          redirect_uri: 'https://example.org/basepath/api/auth/callback',
        });

        const cookies = {} as any;

        await setStateCookieValue(cookies, {
          returnUrl: '/',
        });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          appUrl: 'https://example.org/basepath',
        });

        const req = new TestReq({
          cookies,
          url: `/api/auth/callback?state=peace&code=code`,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org/basepath/');
      });

      it('should throw an OP Error if callback has error', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const req = new TestReq({
          cookies,
          url: `https://example.com/auth/api/callback?state=peace&error=something_went_wrong&error_description=huge%20mistake`,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        const onError = vi.fn();

        await instance.callback(req, res, { onError });

        expect(onError).toBeCalledTimes(1);

        const error = onError.mock.calls[0][0];

        expect(error).toBeInstanceOf(MonoCloudOPError);
        expect(error).toEqual(
          expect.objectContaining({
            error: 'something_went_wrong',
            errorDescription: 'huge mistake',
          })
        );
      });

      it('should execute custom onError function if provided', async () => {
        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies: {},
          url: `/api/auth/callback?state=peace&code=code`,
          method: 'GET',
        });

        const onError = vi.fn();

        await instance.callback(req, new TestRes({}), { onError });

        expect(onError).toHaveBeenCalledTimes(1);
      });

      it('should return internal server error if state is not found', async () => {
        const cookies = { state: { value: 'null' } } as any;

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.statusCode).toBe(500);
      });

      it('should return internal server error if authorization code is not found in returned callback url', async () => {
        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
          url: `https://example.org/callback?state=peace`,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.statusCode).toBe(500);
      });

      it('should return internal server error if jwks endpoint returns an error', async () => {
        setupTokenEndpoint();

        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
          url: `/auth/api/callback?state=peace&code=code`,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.statusCode).toBe(500);
      });

      [
        {
          authParams: {
            scope: 'abc',
          },
        },

        {
          authParams: {
            response_type: 'anything other than code',
          },
        },

        {
          authParams: {
            response_mode: 'invalid',
          },
        },
        { userinfo: null },
      ].forEach(opt => {
        it('should return internal server error if wrong callback options are passed in', async () => {
          const instance = getConfiguredInstance();

          const req = new TestReq({
            method: 'GET',
          });
          const res = new TestRes();

          await instance.callback(req, res, opt as any);

          expect(res.res.statusCode).toBe(500);
        });
      });

      it('can pass in a custom redirect uri in options', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        setupTokenEndpoint({
          redirect_uri: 'https://example.org/custom',
        });

        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          routes: {
            callback: '/custom',
          },
        });

        const req = new TestReq({
          cookies,
          url: '/custom?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org');
        expect(cookies.state).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });

        assertSessionCookieValue(cookies, {
          lifetime: { c: now(), u: now(), e: now() + 86400 },
          session: {
            authorizedScopes: expect.any(String),
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: expect.any(Number),
                scopes: 'openid something',
                requestedScopes: 'openid profile read:customer',
              },
            ],
            idToken: createdIdToken.idToken,
            refreshToken: 'rt',
            user: {
              sub_jwk: createdIdToken.key,
              sub: createdIdToken.sub,
              username: 'oooooooooosername',
            },
          },
        });
      });

      it('can pass in a custom redirect uri in options (with base path)', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        setupTokenEndpoint({
          redirect_uri: 'https://example.org/basepath/custom',
        });

        const cookies = {} as any;

        await setStateCookieValue(cookies, {
          returnUrl: '/',
        });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          routes: {
            callback: '/custom',
          },
          appUrl: 'https://example.org/basepath',
        });

        const req = new TestReq({
          cookies,
          url: '/custom?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org/basepath/');
      });

      it('can pass in a custom redirect uri in callback handler options, overriding the options', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        setupTokenEndpoint({
          redirect_uri: 'https://example.org/custom/handler',
        });

        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          routes: {
            callback: '/custom',
          },
        });

        const req = new TestReq({
          cookies,
          url: '/custom?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res, {
          redirectUri: 'https://example.org/custom/handler',
        });

        expect(res.res.redirectedUrl).toBe('https://example.org');
        expect(cookies.state).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });

        assertSessionCookieValue(cookies, {
          lifetime: { c: now(), u: now(), e: now() + 86400 },
          session: {
            authorizedScopes: expect.any(String),
            accessTokens: [
              {
                accessToken: expect.any(String),
                accessTokenExpiration: expect.any(Number),
                scopes: expect.any(String),
                requestedScopes: expect.any(String),
              },
            ],
            idToken: createdIdToken.idToken,
            refreshToken: 'rt',
            user: {
              sub_jwk: createdIdToken.key,
              sub: createdIdToken.sub,
              username: 'oooooooooosername',
            },
          },
        });
      });

      it('should return internal server error if state parameter mismatches', async () => {
        setupDiscovery();

        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
          url: '/api/auth/callback?state=wrong&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.statusCode).toBe(500);
      });

      it('should return internal server error if nonce parameter mismatches', async () => {
        setupTokenEndpoint();

        const cookies = {} as any;

        await setStateCookieValue(cookies, { nonce: 'wrong' });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const req = new TestReq({
          cookies,
          url: '/custom?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.statusCode).toBe(500);
      });

      it('should return internal server error if the max age specified has passed', async () => {
        createdIdToken = await createTestIdToken({
          username: 'oooooooooosername',
          nonce: '123',
          auth_time: now() - 10000,
        });

        setupTokenEndpoint(undefined, {
          access_token: 'at',
          id_token: createdIdToken.idToken,
          refresh_token: 'rt',
          scope: 'something',
          token_type: 'Bearer',
          expires_in: 999,
        });

        nock('https://example.com')
          .get('/.well-known/openid-configuration/jwks')
          .reply(200, { keys: [createdIdToken.key] });

        nock('https://example.com').get('/connect/userinfo').reply(200, {
          sub: createdIdToken.sub,
          username: 'oooooooooosername',
        });

        const cookies = {} as any;

        await setStateCookieValue(cookies, { maxAge: 100 });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const req = new TestReq({
          cookies,
          url: '/custom?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.statusCode).toBe(500);
      });

      it('can add custom fields to session by passing in onSessionCreating', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        setupTokenEndpoint();

        const cookies = {} as any;

        await setStateCookieValue(cookies, { appState: '{"test":1}' });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          userInfo: true,
          onSessionCreating: (session, idToken, userInfo, state) => {
            expect(state).toEqual({ test: 1 });
            expect(idToken).toBeDefined();
            expect(userInfo).toBeDefined();
            session.test = 1;
          },
        });

        const req = new TestReq({
          cookies,
          url: 'api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org');
        expect(cookies.state).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });

        assertSessionCookieValue(cookies, {
          lifetime: { c: now(), u: now(), e: now() + 86400 },
          session: {
            authorizedScopes: expect.any(String),
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: expect.any(Number),
                scopes: expect.any(String),
                requestedScopes: expect.any(String),
              },
            ],
            idToken: createdIdToken.idToken,
            refreshToken: 'rt',
            user: {
              sub_jwk: createdIdToken.key,
              sub: createdIdToken.sub,
              username: 'oooooooooosername',
              test: '123',
            },
            test: 1,
          },
        });
      });

      it('should redirect to app url if state does not have a redirect url', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        setupTokenEndpoint();

        const cookies = {} as any;

        await setStateCookieValue(cookies, { returnUrl: undefined });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const req = new TestReq({
          cookies,
          url: 'api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org');
      });

      it('should redirect to app url if state does not have a redirect url (with base path)', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        setupTokenEndpoint({
          redirect_uri: 'https://example.org/basepath/api/auth/callback',
        });

        const cookies = {} as any;

        await setStateCookieValue(cookies, { returnUrl: undefined });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          appUrl: 'https://example.org/basepath',
        });

        const req = new TestReq({
          cookies,
          url: 'api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org/basepath');
      });

      ['/test', 'https://example.org/test'].forEach(url => {
        it(`should redirect to the return url from the state if the url is ${url.startsWith('/') ? 'Relative' : 'Absolute'}`, async () => {
          nock('https://example.com')
            .get('/.well-known/openid-configuration')
            .reply(200, defaultMetadata);

          setupTokenEndpoint();

          const cookies = {} as any;

          await setStateCookieValue(cookies, { returnUrl: url });

          const instance = getConfiguredInstance({
            idTokenSigningAlg: 'ES256',
          });

          const req = new TestReq({
            cookies,
            url: 'api/auth/callback?state=peace&code=code',
            method: 'GET',
          });
          const res = new TestRes(cookies);

          await instance.callback(req, res);

          expect(res.res.redirectedUrl).toBe('https://example.org/test');
        });
      });

      ['/test', 'https://example.org/basepath/test'].forEach(url => {
        it(`should redirect to the return url from the state if the url is ${url.startsWith('/') ? 'Relative' : 'Absolute'} (with basepath)`, async () => {
          nock('https://example.com')
            .get('/.well-known/openid-configuration')
            .reply(200, defaultMetadata);

          setupTokenEndpoint({
            redirect_uri: 'https://example.org/basepath/api/auth/callback',
          });

          const cookies = {} as any;

          await setStateCookieValue(cookies, { returnUrl: url });

          const instance = getConfiguredInstance({
            idTokenSigningAlg: 'ES256',
            appUrl: 'https://example.org/basepath',
          });

          const req = new TestReq({
            cookies,
            url: 'api/auth/callback?state=peace&code=code',
            method: 'GET',
          });
          const res = new TestRes(cookies);

          await instance.callback(req, res);

          expect(res.res.redirectedUrl).toBe(
            'https://example.org/basepath/test'
          );
        });
      });

      it('should redirect to the app url if the returnUrl in the state is invalid', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        setupTokenEndpoint();

        const cookies = {} as any;

        await setStateCookieValue(cookies, {
          returnUrl: 'https://someoneelse.com/cb',
        });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const req = new TestReq({
          cookies,
          url: 'api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org');
      });

      it('should redirect to the app url if the returnUrl in the state is invalid (with base path)', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        setupTokenEndpoint({
          redirect_uri: 'https://example.org/basepath/api/auth/callback',
        });

        const cookies = {} as any;

        await setStateCookieValue(cookies, {
          returnUrl: 'https://someoneelse.com/cb',
        });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          appUrl: 'https://example.org/basepath',
        });

        const req = new TestReq({
          cookies,
          url: 'api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org/basepath');
      });

      it('should not fetch from userinfo if options.userInfo explicitly to false', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        setupTokenEndpoint();

        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const req = new TestReq({
          cookies,
          url: 'api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res, { userInfo: false });

        expect(res.res.redirectedUrl).toBe('https://example.org');

        assertSessionCookieValue(cookies, {
          lifetime: { c: now(), u: now(), e: now() + 86400 },
          session: {
            authorizedScopes: expect.any(String),
            accessTokens: [
              {
                accessToken: expect.any(String),
                accessTokenExpiration: expect.any(Number),
                scopes: expect.any(String),
                requestedScopes: expect.any(String),
              },
            ],
            idToken: createdIdToken.idToken,
            refreshToken: 'rt',
            user: {
              sub_jwk: createdIdToken.key,
              sub: createdIdToken.sub,
              username: 'oooooooooosername',
            },
          },
        });
      });

      it('should return internal server error if the userinfo endpoint returns an error', async () => {
        setupTokenEndpoint();

        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const req = new TestReq({
          cookies,
          url: 'api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.statusCode).toBe(500);
      });

      it('should filter out the configured claims', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        setupTokenEndpoint();

        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          filteredIdTokenClaims: ['nonce', 'sub_jwk'],
        });

        const req = new TestReq({
          cookies,
          url: '/api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        assertSessionCookieValue(cookies, {
          lifetime: { c: now(), u: now(), e: now() + 86400 },
          session: {
            authorizedScopes: expect.any(String),
            accessTokens: [
              {
                accessToken: expect.any(String),
                accessTokenExpiration: expect.any(Number),
                scopes: expect.any(String),
                requestedScopes: expect.any(String),
              },
            ],
            idToken: createdIdToken.idToken,
            refreshToken: 'rt',
            user: {
              username: 'oooooooooosername',
              sub: createdIdToken.sub,
              iss: 'https://example.com',
              aud: '__test_client_id__',
              exp: 1330688389,
              iat: 1330688329,
            },
          },
        });
      });

      it('should return bad request if there is an op error', async () => {
        nock(testConfig.tenantDomain)
          .get('/.well-known/openid-configuration')
          .reply(400, {
            error: 'server_error',
            error_description: 'bad things are happening',
          });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const cookies = {};

        await setStateCookieValue(cookies);

        const req = new TestReq({
          cookies,
          url: '/api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.statusCode).toBe(500);
      });

      ['DELETE', 'PUT', 'PATCH', 'OPTIONS', 'TRACE', 'HEAD'].forEach(
        (method: any) => {
          it('should return method not allowed for unsupported methods', async () => {
            setupDiscovery();

            const instance = getConfiguredInstance({
              idTokenSigningAlg: 'ES256',
            });

            const cookies = {};

            await setStateCookieValue(cookies);

            const req = new TestReq({
              cookies,
              url: '/api/auth/callback?state=peace&code=code',
              method,
            });
            const res = new TestRes(cookies);

            await instance.callback(req, res);

            expect(res.res.statusCode).toBe(405);
          });
        }
      );
    });

    describe('userinfo', () => {
      const frozenTimeMs = 1330688329321;

      beforeEach(() => {
        freeze(frozenTimeMs);

        nock('https://example.com')
          .matchHeader('authorization', 'Bearer at')
          .get('/connect/userinfo')
          .reply(200, {
            sub: 'id',
            username: 'username',
            test: 'updated',
            new: 'field',
          });
      });

      afterEach(reset);

      it('should perform a userinfo request when customized through options', async () => {
        setupDiscovery({
          userinfo_endpoint: 'https://example.com/connect/userinfo',
        });

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            authorizedScopes: 'openid profile read:customer',
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'openid profile read:customer',
                requestedScopes: 'openid profile read:customer',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({ refetchUserInfo: true });

        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res);

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: 'updated',
              new: 'field',
            },
            idToken: 'a.b.c',
            refreshToken: 'rt',
            authorizedScopes: 'openid profile read:customer',
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'openid profile read:customer',
                requestedScopes: 'openid profile read:customer',
              },
            ],
          },
          lifetime: { c: oldTime, u: now(), e: oldTime + 86400 },
        });
      });

      it('should perform a userinfo request when passed through query', async () => {
        setupDiscovery({
          userinfo_endpoint: 'https://example.com/connect/userinfo',
        });

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            authorizedScopes: 'openid profile read:customer',
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'openid profile read:customer',
                requestedScopes: 'openid profile read:customer',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({ refetchUserInfo: false });

        const req = new TestReq({
          cookies,
          query: { refresh: 'true' },
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res, { refresh: false });

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: 'updated',
              new: 'field',
            },
            idToken: 'a.b.c',
            refreshToken: 'rt',
            authorizedScopes: 'openid profile read:customer',
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'openid profile read:customer',
                requestedScopes: 'openid profile read:customer',
              },
            ],
          },
          lifetime: { c: oldTime, u: now(), e: oldTime + 86400 },
        });
      });

      it('should execute custom onError function if provided', async () => {
        const instance = getConfiguredInstance();

        const req = new TestReq({ cookies: {}, method: 'GET' });

        const onError = vi.fn();

        await instance.userInfo(req, new TestRes({}), {
          onError,
          refresh: 'FORCE ERROR' as unknown as boolean,
        });

        expect(onError).toHaveBeenCalledTimes(1);
      });

      it('should perform a userinfo request when customized through handler options and will override options', async () => {
        setupDiscovery({
          userinfo_endpoint: 'https://example.com/connect/userinfo',
        });

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            authorizedScopes: 'openid profile read:customer',
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'openid profile read:customer',
                requestedScopes: 'openid profile read:customer',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({ refetchUserInfo: false });

        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res, { refresh: true });

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: 'updated',
              new: 'field',
            },
            authorizedScopes: 'openid profile read:customer',
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'openid profile read:customer',
                requestedScopes: 'openid profile read:customer',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, u: now(), e: oldTime + 86400 },
        });
      });

      it('should not perform a userinfo request when customized through handler options and will override options', async () => {
        setupDiscovery({
          userinfo_endpoint: 'https://example.com/userinfo',
        });

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'something',
                requestedScopes: 'something',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({ refetchUserInfo: true });

        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res, { refresh: false });

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'something',
                requestedScopes: 'something',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });
      });

      it('should not perform a userinfo request through query if allowQueryParamOverrides is false', async () => {
        setupDiscovery({
          userinfo_endpoint: 'https://example.com/userinfo',
        });

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'something',
                requestedScopes: 'something',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({
          refetchUserInfo: false,
          allowQueryParamOverrides: false,
        });

        const req = new TestReq({
          cookies,
          query: { refresh: 'true' },
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res, { refresh: false });

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'something',
                requestedScopes: 'something',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });
      });

      it('should not perform a userinfo request when customized through options', async () => {
        setupDiscovery({
          userinfo_endpoint: 'https://example.com/userinfo',
        });

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'something',
                requestedScopes: 'something',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({ refetchUserInfo: false });

        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res);

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'something',
                requestedScopes: 'something',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });
      });

      it('should return with no cache header and no content if session is not found', async () => {
        const cookies = {} as any;

        const instance = getConfiguredInstance();

        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res);

        expect(res.res.noCacheSet).toBe(true);
        expect(res.res.statusCode).toBe(204);
      });

      [{ refresh: 54 }, []].forEach(opt => {
        it('should return internal server error if options is a wrong object', async () => {
          const cookies = {} as any;

          const instance = getConfiguredInstance();

          const req = new TestReq({ cookies, method: 'GET' });
          const res = new TestRes(cookies);

          await instance.userInfo(req, res, opt as any);

          expect(res.res.statusCode).toBe(500);
        });
      });

      it('can add custom fields to session by passing in onSessionCreating', async () => {
        setupDiscovery({
          userinfo_endpoint: 'https://example.com/connect/userinfo',
        });

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            authorizedScopes: 'openid profile read:customer',
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'openid profile read:customer',
                requestedScopes: 'openid profile read:customer',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({
          refetchUserInfo: true,
          onSessionCreating: (session, idToken, userInfo, state) => {
            expect(state).toBeUndefined();
            expect(idToken).toBeUndefined();
            expect(userInfo).toBeDefined();
            session.test = 1;
          },
        });

        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res);

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: 'updated',
              new: 'field',
            },
            authorizedScopes: 'openid profile read:customer',
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'openid profile read:customer',
                requestedScopes: 'openid profile read:customer',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
            test: 1,
          },
          lifetime: { c: oldTime, u: now(), e: oldTime + 86400 },
        });
      });

      it('returns no cache and no content if the session was not updated', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            authorizedScopes: 'openid profile read:customer',
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'openid profile read:customer',
                requestedScopes: 'openid profile read:customer',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({
          refetchUserInfo: true,
        });

        // Find a better way than this later.
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        instance.sessionService.updateSession = (): Promise<boolean> =>
          Promise.resolve(false);

        const req = new TestReq({ cookies, method: 'GET' });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res);

        expect(res.res.noCacheSet).toBe(true);
        expect(res.res.statusCode).toBe(204);

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            authorizedScopes: 'openid profile read:customer',
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: oldTime + 5,
                scopes: 'openid profile read:customer',
                requestedScopes: 'openid profile read:customer',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });
      });

      it('should return bad request if there is an op error', async () => {
        nock('https://another.one').get('/connect/userinfo').reply(400, {
          error: 'server_error',
          error_description: 'bad things are happening',
        });

        const instance = getConfiguredInstance({
          tenantDomain: 'https://another.one',
          idTokenSigningAlg: 'ES256',
        });

        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            authorizedScopes: 'openid profile read:customer',
            accessTokens: [
              {
                accessToken: 'at',
                accessTokenExpiration: now() + 5,
                scopes: 'openid profile read:customer',
                requestedScopes: 'openid profile read:customer',
              },
            ],
            idToken: 'a.b.c',
            refreshToken: 'rt',
          },
          lifetime: { c: now(), u: now(), e: now() + 86400 },
        });

        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res, { refresh: true });

        expect(res.res.statusCode).toBe(500);
      });

      ['DELETE', 'PUT', 'POST', 'PATCH', 'OPTIONS', 'TRACE', 'HEAD'].forEach(
        (method: any) => {
          it('should return method not allowed for unsupported methods', async () => {
            setupDiscovery({
              userinfo_endpoint: 'https://example.com/userinfo',
            });

            const cookies = {} as any;

            const instance = getConfiguredInstance();

            const req = new TestReq({ cookies, method });
            const res = new TestRes(cookies);

            await instance.userInfo(req, res);

            expect(res.res.statusCode).toBe(405);
          });
        }
      );
    });

    describe('signout', () => {
      it('should redirect to endSessionUrl', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://example.com/connect/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          session: {},
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res);

        expect(res.res.redirectedUrl).toBe(
          `https://example.com/connect/endsession?client_id=__test_client_id__&post_logout_redirect_uri=${encodeURIComponent('https://example.org')}`
        );
        expect(cookies.session).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });
      });

      it('should execute custom onError function if provided', async () => {
        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies: {},
          method: 'GET',
        });

        const onError = vi.fn();

        await instance.signOut(req, new TestRes({}), {
          onError,
          federatedSignOut: 'FORCE ERROR' as unknown as boolean,
        });

        expect(onError).toHaveBeenCalledTimes(1);
      });

      it('should redirect to endSessionUrl (with base path)', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://example.com/connect/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          session: {},
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance({
          appUrl: 'https://example.org/basepath',
        });

        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res);

        expect(res.res.redirectedUrl).toBe(
          `https://example.com/connect/endsession?client_id=__test_client_id__&post_logout_redirect_uri=${encodeURIComponent('https://example.org/basepath')}`
        );
        expect(cookies.session).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });
      });

      it('should redirect to endSessionUrl with post logout redirect uri and id token hint', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://example.com/connect/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          session: {
            idToken: 'a.b.c',
          },
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance({
          postLogoutRedirectUri: '/test',
        });

        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res);

        expect(res.res.redirectedUrl).toBe(
          `https://example.com/connect/endsession?client_id=__test_client_id__&id_token_hint=${encodeURIComponent('a.b.c')}&post_logout_redirect_uri=${encodeURIComponent('https://example.org/test')}`
        );

        expect(cookies.session).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });
      });

      it('should redirect to endSessionUrl with post logout redirect uri and id token hint (with base path)', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://example.com/connect/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          session: {
            idToken: 'a.b.c',
          },
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance({
          postLogoutRedirectUri: '/test',
          appUrl: 'https://example.org/basepath',
        });

        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res);

        expect(res.res.redirectedUrl).toBe(
          `https://example.com/connect/endsession?client_id=__test_client_id__&id_token_hint=${encodeURIComponent('a.b.c')}&post_logout_redirect_uri=${encodeURIComponent('https://example.org/basepath/test')}`
        );

        expect(cookies.session).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });
      });

      it('should redirect to endSessionUrl with post logout configured through handler options', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://example.com/connect/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          session: {},
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res, { postLogoutRedirectUri: '/test' });

        expect(res.res.redirectedUrl).toBe(
          `https://example.com/connect/endsession?client_id=__test_client_id__&post_logout_redirect_uri=${encodeURIComponent('https://example.org/test')}`
        );

        expect(cookies.session).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });
      });

      it('should redirect to endSessionUrl with post logout configured through handler options (with base path)', async () => {
        nock('https://example.com')
          .get('/.well-known/openid-configuration')
          .reply(200, defaultMetadata);

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          session: {},
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance({
          appUrl: 'https://example.org/basepath',
        });

        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res, { postLogoutRedirectUri: '/test' });

        expect(res.res.redirectedUrl).toBe(
          `https://example.com/connect/endsession?client_id=__test_client_id__&post_logout_redirect_uri=${encodeURIComponent('https://example.org/basepath/test')}`
        );

        expect(cookies.session).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });
      });

      ['/from/query', 'https://example.org/from/query'].forEach(
        post_logout_url => {
          it('can pickup post_logout_url from query param', async () => {
            setupDiscovery({
              end_session_endpoint: 'https://example.com/connect/endsession',
            });

            const cookies = {} as any;

            await setSessionCookieValue(cookies, {
              session: {},
              lifetime: { c: now(), e: now() + 86400, u: now() },
            });

            const instance = getConfiguredInstance();

            const req = new TestReq({
              cookies,
              query: { post_logout_url },
              method: 'GET',
            });
            const res = new TestRes(cookies);

            await instance.signOut(req, res);

            expect(res.res.redirectedUrl).toBe(
              `https://example.com/connect/endsession?client_id=__test_client_id__&post_logout_redirect_uri=${encodeURIComponent('https://example.org/from/query')}`
            );

            expect(cookies.session).toEqual({
              value: '',
              options: {
                domain: undefined,
                expires: new Date(0),
                httpOnly: true,
                path: '/',
                sameSite: 'lax',
                secure: true,
              },
            });
          });
        }
      );

      ['/from/query', 'https://example.org/basepath/from/query'].forEach(
        post_logout_url => {
          it('can pickup post_logout_url from query param (with basepath)', async () => {
            setupDiscovery({
              end_session_endpoint: 'https://example.com/connect/endsession',
            });

            const cookies = {} as any;

            await setSessionCookieValue(cookies, {
              session: {},
              lifetime: { c: now(), e: now() + 86400, u: now() },
            });

            const instance = getConfiguredInstance({
              appUrl: 'https://example.org/basepath',
            });

            const req = new TestReq({
              cookies,
              query: { post_logout_url },
              method: 'GET',
            });
            const res = new TestRes(cookies);

            await instance.signOut(req, res);

            expect(res.res.redirectedUrl).toBe(
              `https://example.com/connect/endsession?client_id=__test_client_id__&post_logout_redirect_uri=${encodeURIComponent('https://example.org/basepath/from/query')}`
            );

            expect(cookies.session).toEqual({
              value: '',
              options: {
                domain: undefined,
                expires: new Date(0),
                httpOnly: true,
                path: '/',
                sameSite: 'lax',
                secure: true,
              },
            });
          });
        }
      );

      it('should not override post_logout_url from query param if allowQueryParamOverrides is false', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://example.com/connect/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          session: {},
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance({
          allowQueryParamOverrides: false,
        });

        const req = new TestReq({
          cookies,
          query: {
            post_logout_url: 'https://example.org/from/query/malicious',
          },
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res, {
          postLogoutRedirectUri: 'https://example.com',
        });

        expect(res.res.redirectedUrl).toBe(
          `https://example.com/connect/endsession?client_id=__test_client_id__&post_logout_redirect_uri=${encodeURIComponent('https://example.com')}`
        );

        expect(cookies.session).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });
      });

      it('invalid post_logout_url from query param does not override', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://example.com/connect/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          session: {},
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
          query: { post_logout_url: '"' },
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res, {
          postLogoutRedirectUri: 'https://example.com',
        });

        expect(res.res.redirectedUrl).toBe(
          `https://example.com/connect/endsession?client_id=__test_client_id__&post_logout_redirect_uri=${encodeURIComponent('https://example.com')}`
        );

        expect(cookies.session).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });
      });

      [
        { federatedSignOut: 23 },
        { post_logout_url: Symbol('test') },
        { signOutParams: [] },
      ].forEach((opt, i) => {
        it(`should return internal server error for invalid configuration options. ${i + 1} of 3`, async () => {
          setupDiscovery({
            end_session_endpoint: 'https://example.com/connect/endsession',
          });

          const cookies = {} as any;

          await setSessionCookieValue(cookies, {
            session: {},
            lifetime: { c: now(), e: now() + 86400, u: now() },
          });

          const instance = getConfiguredInstance();

          const req = new TestReq({
            cookies,
            method: 'GET',
          });
          const res = new TestRes(cookies);

          await instance.signOut(req, res, opt as any);

          expect(res.res.statusCode).toBe(500);
        });
      });

      it('should redirect to app url if there is no session', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://example.com/connect/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org');
      });

      it('should redirect to app url if there is no session (with basepath)', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://example.com/connect/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance({
          appUrl: 'https://example.org/basepath',
        });

        const req = new TestReq({
          cookies,
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org/basepath');
      });

      [
        [{ federatedSignOut: false }, {}],
        [{}, { federatedSignOut: false }],
      ].forEach(([opt, handlerOpt], i) => {
        it(`should redirect to app url if federatedSignOut is false ${i + 1} of 2`, async () => {
          setupDiscovery({
            end_session_endpoint: 'https://example.com/connect/endsession',
          });

          const cookies = {} as any;

          await setSessionCookieValue(cookies, {
            session: {},
            lifetime: { c: now(), e: now() + 86400, u: now() },
          });

          const instance = getConfiguredInstance(opt as any);

          const req = new TestReq({
            cookies,
            method: 'GET',
          });
          const res = new TestRes(cookies);

          await instance.signOut(req, res, handlerOpt);

          expect(res.res.redirectedUrl).toBe(`https://example.org`);

          expect(cookies.session).toEqual({
            value: '',
            options: {
              domain: undefined,
              expires: new Date(0),
              httpOnly: true,
              path: '/',
              sameSite: 'lax',
              secure: true,
            },
          });
        });
      });

      [
        [{ federatedSignOut: false }, {}],
        [{}, { federatedSignOut: false }],
      ].forEach(([opt, handlerOpt], i) => {
        it(`should redirect to app url if federatedSignOut is false ${i + 1} of 2 (with base path)`, async () => {
          setupDiscovery({
            end_session_endpoint: 'https://example.com/connect/endsession',
          });

          const cookies = {} as any;

          await setSessionCookieValue(cookies, {
            session: {},
            lifetime: { c: now(), e: now() + 86400, u: now() },
          });

          const instance = getConfiguredInstance({
            ...opt,
            appUrl: 'https://example.org/basepath',
          } as any);

          const req = new TestReq({
            cookies,
            method: 'GET',
          });
          const res = new TestRes(cookies);

          await instance.signOut(req, res, handlerOpt);

          expect(res.res.redirectedUrl).toBe(`https://example.org/basepath`);

          expect(cookies.session).toEqual({
            value: '',
            options: {
              domain: undefined,
              expires: new Date(0),
              httpOnly: true,
              path: '/',
              sameSite: 'lax',
              secure: true,
            },
          });
        });
      });

      it('should pickup federated signout from query', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://example.com/connect/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          session: {},
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance({ federatedSignOut: false });

        const req = new TestReq({
          cookies,
          query: {
            federated: 'true',
          },
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res, { federatedSignOut: false });

        expect(res.res.redirectedUrl).toBe(
          `https://example.com/connect/endsession?client_id=__test_client_id__&post_logout_redirect_uri=${encodeURIComponent('https://example.org')}`
        );

        expect(cookies.session).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });
      });

      ['DELETE', 'PUT', 'POST', 'PATCH', 'OPTIONS', 'TRACE', 'HEAD'].forEach(
        (method: any) => {
          it('should return method not allowed for unsupported methods', async () => {
            setupDiscovery({
              userinfo_endpoint: 'https://example.com/userinfo',
            });

            const cookies = {} as any;

            const instance = getConfiguredInstance();

            const req = new TestReq({ cookies, method });
            const res = new TestRes(cookies);

            await instance.signOut(req, res);

            expect(res.res.statusCode).toBe(405);
          });
        }
      );
    });

    describe('backchannelLogout', () => {
      const createBackchannelLogout = async (claims = {}): Promise<any> => {
        const kp = await jose.generateKeyPair('ES256', { extractable: true });
        const jwk = await jose.exportJWK(kp.publicKey);
        const sub = await jose.calculateJwkThumbprint(jwk);
        return {
          token: await new jose.SignJWT({
            sub_jwk: jwk,
            sub: sub,
            sid: 'sid',
            events: {
              'http://schemas.openid.net/event/backchannel-logout': {},
            },
            ...claims,
          })
            .setIssuedAt()
            .setProtectedHeader({ alg: 'ES256' })
            .setIssuer('https://example.com')
            .setAudience('__test_client_id__')
            .setExpirationTime('1m')
            .sign(kp.privateKey),
          key: jwk,
          sub,
        };
      };

      it('should return no cache and not found if no back channel handler is found', () => {
        const instance = getConfiguredInstance();
        const res = new TestRes();

        instance.backChannelLogout(new TestReq(), res);

        expect(res.res.noCacheSet).toBe(true);
        expect(res.res.statusCode).toBe(404);
      });

      it('should perform a backchannel logout', async () => {
        const backchannelLogoutToken = await createBackchannelLogout();
        nock('https://example.com')
          .get('/jwks')
          .reply(200, { keys: [backchannelLogoutToken.key] });

        setupDiscovery({ jwks_uri: 'https://example.com/jwks' });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          onBackChannelLogout: (sub, sid) => {
            expect(sub).toBe(backchannelLogoutToken.sub);
            expect(sid).toBe('sid');
          },
        });

        const req = new TestReq({
          method: 'POST',
          body: { logout_token: backchannelLogoutToken.token },
        });
        const res = new TestRes();

        await instance.backChannelLogout(req, res);

        expect(res.res.statusCode).toBe(204);
      });

      it('should return a method not allowed if the request was not a post', async () => {
        const instance = getConfiguredInstance({
          onBackChannelLogout: () => {},
        });

        const req = new TestReq({
          method: 'GET',
          body: { logout_token: 'token' },
        });
        const res = new TestRes();

        await instance.backChannelLogout(req, res);

        expect(res.res.statusCode).toBe(405);
      });

      it('should return internal server error if the logout token was not found in the body', async () => {
        const instance = getConfiguredInstance({
          onBackChannelLogout: () => {},
        });

        const req = new TestReq({
          method: 'POST',
          body: {},
        });
        const res = new TestRes();

        await instance.backChannelLogout(req, res);

        expect(res.res.noCacheSet).toBe(true);
        expect(res.res.statusCode).toBe(500);
      });

      it('should return internal server error if the event is not an object', async () => {
        const backchannelLogoutToken = await createBackchannelLogout({
          events: {
            'http://schemas.openid.net/event/backchannel-logout': null,
          },
        });
        nock('https://example.com')
          .get('/jwks')
          .reply(200, { keys: [backchannelLogoutToken.key] });

        setupDiscovery({ jwks_uri: 'https://example.com/jwks' });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          onBackChannelLogout: (sub, sid) => {
            expect(sub).toBe(backchannelLogoutToken.sub);
            expect(sid).toBe('sid');
          },
        });

        const req = new TestReq({
          method: 'POST',
          body: { logout_token: backchannelLogoutToken.token },
        });
        const res = new TestRes();

        await instance.backChannelLogout(req, res);

        expect(res.res.noCacheSet).toBe(true);
        expect(res.res.statusCode).toBe(500);
      });

      [
        { sid: undefined, sub: undefined },
        { nonce: 'test' },
        { events: undefined },
        { events: 1 },
      ].forEach((x, i) => {
        it(`should return bad request if the logout token is invalid ${i + 1} of 4`, async () => {
          const backchannelLogoutToken = await createBackchannelLogout(x);
          nock('https://example.com')
            .get('/jwks')
            .reply(200, { keys: [backchannelLogoutToken.key] });

          setupDiscovery({ jwks_uri: 'https://example.com/jwks' });

          const instance = getConfiguredInstance({
            idTokenSigningAlg: 'ES256',
            onBackChannelLogout: (sub, sid) => {
              expect(sub).toBe(backchannelLogoutToken.sub);
              expect(sid).toBe('sid');
            },
          });

          const req = new TestReq({
            method: 'POST',
            body: { logout_token: backchannelLogoutToken.token },
          });
          const res = new TestRes();

          await instance.backChannelLogout(req, res);

          expect(res.res.noCacheSet).toBe(true);
          expect(res.res.statusCode).toBe(500);
        });
      });

      it('should return bad request if there is an op error', async () => {
        nock(testConfig.tenantDomain)
          .get('/.well-known/openid-configuration')
          .reply(400, {
            error: 'server_error',
            error_description: 'bad things are happening',
          });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          onBackChannelLogout: () => {},
        });

        const req = new TestReq({
          method: 'POST',
          body: { logout_token: 'token' },
        });
        const res = new TestRes();

        await instance.backChannelLogout(req, res);

        expect(res.res.statusCode).toBe(500);
      });
    });
  });

  describe('instance helpers', () => {
    it('should return options configured by the client when instance.getOptions() is called', () => {
      const instance = new MonoCloudCoreClient(defaultConfig);

      expect(instance.getOptions()).toEqual(getOptions(defaultConfig));
    });

    it('should not throw validation error during runtime if already validated', () => {
      const instance = new MonoCloudCoreClient({});

      // @ts-expect-error FOR TEST COVERAGE
      instance.optionsValidated = true;

      // @ts-expect-error FOR TEST COVERAGE
      expect(() => instance.validateOptions()).not.toThrow();
    });

    it('should destroy session', async () => {
      const instance = getConfiguredInstance({
        session: { cookie: { name: 'destroysessioncookie' } },
      });

      const cookies: any = {
        destroysessioncookie: {
          value: await getSessionCookie({ session: defaultSessionData() }),
        },
      };

      await instance.destroySession(
        new TestReq({ cookies }),
        new TestRes(cookies)
      );

      expect(cookies.destroysessioncookie).toEqual({
        value: '',
        options: {
          domain: undefined,
          expires: new Date(0),
          httpOnly: true,
          path: '/',
          sameSite: 'lax',
          secure: true,
        },
      });
    });

    it('isAuthenticated should return true if the request is authenticated and has a session', async () => {
      const cookies = {};

      await setSessionCookieValue(cookies, {
        session: { user: { sub: 'id' } },
        lifetime: { u: now(), e: now() + 4, c: now() },
      });

      const req = new TestReq({ cookies });
      const res = new TestRes();

      const instance = getConfiguredInstance();

      expect(await instance.isAuthenticated(req, res)).toBe(true);
    });

    it('isAuthenticated should return false if the request is not authenticated', async () => {
      const cookies = {};

      const req = new TestReq({ cookies });
      const res = new TestRes();

      const instance = getConfiguredInstance();
      expect(await instance.isAuthenticated(req, res)).toBe(false);
    });

    it('getSession should return the session', async () => {
      const cookies = {};

      await setSessionCookieValue(cookies, {
        session: {
          user: { sub: 'id' },
          scopes: 'abc',
          accessToken: 'at',
          accessTokenExpiration: 8,
          idToken: 'idtoken',
          refreshToken: 'rt',
        },
        lifetime: { u: now(), e: now() + 4, c: now() },
      });

      const req = new TestReq({ cookies });
      const res = new TestRes();

      const instance = getConfiguredInstance();

      const session = await instance.getSession(req, res);

      expect(session).toEqual({
        user: { sub: 'id' },
        scopes: 'abc',
        accessToken: 'at',
        accessTokenExpiration: 8,
        idToken: 'idtoken',
        refreshToken: 'rt',
      });
    });

    it('updateSession should update the session', async () => {
      const frozenTimeMs = 1330688329321;

      freeze(frozenTimeMs);

      const cookies = {};

      const timeOld = now();
      await setSessionCookieValue(cookies, {
        session: {
          user: { sub: 'id' },
          scopes: 'abc',
          accessToken: 'at',
          accessTokenExpiration: 8,
          idToken: 'idtoken',
          refreshToken: 'rt',
        },
        lifetime: { u: timeOld, e: timeOld + 86400, c: timeOld },
      });

      const req = new TestReq({ cookies });
      const res = new TestRes(cookies);

      const instance = getConfiguredInstance();

      travel(frozenTimeMs + 2000);

      await instance.updateSession(req, res, {
        test: 1,
        user: {} as MonoCloudUser,
      });

      assertSessionCookieValue(cookies, {
        session: {
          user: {},
          test: 1,
        },
        lifetime: { u: now(), e: timeOld + 86400, c: timeOld },
      });

      reset();
    });

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

      it('should return the tokens', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: {
            user: {} as MonoCloudUser,
            authorizedScopes: 'openid abc',
            accessTokens: [
              {
                scopes: 'openid abc',
                requestedScopes: 'openid abc',
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

        const instance = getConfiguredInstance();

        const tokens = await instance.getTokens(req, res);

        expect(tokens).toEqual({
          accessToken: 'at',
          scopes: 'openid abc',
          requestedScopes: 'openid abc',
          accessTokenExpiration: expect.any(Number),
          idToken: 'idtoken',
          refreshToken: 'rt',
          isExpired: false,
        });
      });

      it('should find the token with the resource from session', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: {
            user: {} as MonoCloudUser,
            authorizedScopes: 'openid abc',
            accessTokens: [
              {
                scopes: 'openid abc',
                requestedScopes: 'openid abc',
                accessToken: 'at',
                resource: 'https://resource.com',
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

        const instance = getConfiguredInstance();

        const tokens = await instance.getTokens(req, res, {
          resource: 'https://resource.com',
          scopes: 'openid abc',
        });

        expect(tokens).toEqual({
          accessToken: 'at',
          scopes: 'openid abc',
          requestedScopes: 'openid abc',
          resource: 'https://resource.com',
          accessTokenExpiration: expect.any(Number),
          idToken: 'idtoken',
          refreshToken: 'rt',
          isExpired: false,
        });
      });

      it('should find the token with the undefined scopes', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: {
            user: {} as MonoCloudUser,
            authorizedScopes: 'openid abc',
            accessTokens: [
              {
                scopes: 'openid abc',
                requestedScopes: undefined,
                accessToken: 'at',
                resource: 'https://resource.com',
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
          resources: [{ resource: 'https://resource.com' }],
        });

        const tokens = await instance.getTokens(req, res, {
          resource: 'https://resource.com',
        });

        expect(tokens).toEqual({
          accessToken: 'at',
          scopes: 'openid abc',
          resource: 'https://resource.com',
          accessTokenExpiration: expect.any(Number),
          idToken: 'idtoken',
          refreshToken: 'rt',
          isExpired: false,
        });
      });

      it('should find the token with scopes defined in indicator options', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: {
            user: {} as MonoCloudUser,
            authorizedScopes: 'openid abc',
            accessTokens: [
              {
                scopes: 'openid abc',
                requestedScopes: 'openid abc',
                accessToken: 'at',
                resource: 'https://resource.com',
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
          resources: [
            { resource: 'https://resource.com', scopes: 'openid abc' },
          ],
        });

        const tokens = await instance.getTokens(req, res, {
          resource: 'https://resource.com',
        });

        expect(tokens).toEqual({
          accessToken: 'at',
          scopes: 'openid abc',
          requestedScopes: 'openid abc',
          resource: 'https://resource.com',
          accessTokenExpiration: expect.any(Number),
          idToken: 'idtoken',
          refreshToken: 'rt',
          isExpired: false,
        });
      });

      it('should refresh the tokens if specified', async () => {
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
            id_token: createdIdToken.idToken,
            refresh_token: 'rt1',
            scope: 'something',
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
            authorizedScopes: 'something',
            accessTokens: [
              {
                requestedScopes: 'something',
                scopes: 'something',
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

        const instance = getConfiguredInstance({ idTokenSigningAlg: 'ES256' });

        const newFrozenTime = frozenTimeMs + 2000;
        travel(newFrozenTime);

        const tokens = await instance.getTokens(req, res, {
          forceRefresh: true,
        });

        expect(tokens).toEqual({
          accessToken: 'at1',
          scopes: 'something',
          requestedScopes: 'something',
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
            authorizedScopes: 'something',
            accessTokens: [
              {
                scopes: 'something',
                requestedScopes: 'something',
                accessToken: 'at1',
                accessTokenExpiration: expect.any(Number),
              },
            ],
            idToken: createdIdToken.idToken,
            refreshToken: 'rt1',
          },
          lifetime: { c: oldTime, e: oldTime + 86400, u: now() },
        });
      });

      it('should not save the new access token in the cookie if RefreshGrantOptions.scopes or RefreshGrantOptions.resource was passed in', async () => {
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
            id_token: createdIdToken.idToken,
            refresh_token: 'rt1',
            scope: 'something',
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
                scopes: 'abc',
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

        const instance = getConfiguredInstance({ idTokenSigningAlg: 'ES256' });

        const newFrozenTime = frozenTimeMs + 2000;
        travel(newFrozenTime);

        const tokens = await instance.getTokens(req, res, {
          forceRefresh: true,
        });

        expect(tokens).toEqual({
          accessToken: 'at1',
          accessTokenExpiration: expect.any(Number),
          scopes: 'something',
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
                accessTokenExpiration: expect.any(Number),
                scopes: 'something',
              },
            ],
            idToken: createdIdToken.idToken,
            refreshToken: 'rt1',
          },
          lifetime: { c: oldTime, e: oldTime + 86400, u: now() },
        });
      });

      it('should throw error if force refresh is true and no refresh token is found', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: {
            user: {} as MonoCloudUser,
            accessTokens: [
              {
                scopes: 'abc',
                accessToken: 'at',
                accessTokenExpiration: now() + 100,
              },
            ],

            idToken: 'idtoken',
          },
          lifetime: { u: now(), e: now() + 86400, c: now() },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        const instance = getConfiguredInstance();

        try {
          await instance.getTokens(req, res, {
            forceRefresh: true,
          });
        } catch (error) {
          expect(error).toBeInstanceOf(MonoCloudValidationError);
          expect((error as any).message).toBe(
            'Session does not contain refresh token'
          );
        }
      });

      it('should refresh the tokens and fetch from userinfo using the new access token if specified', async () => {
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
            id_token: createdIdToken.idToken,
            refresh_token: 'rt1',
            scope: 'openid abc',
            token_type: 'Bearer',
            expires_in: 999,
          });

        nock('https://example.com')
          .matchHeader('authorization', 'Bearer at1')
          .get('/connect/userinfo')
          .reply(200, {
            sub: createdIdToken.sub,
            username: 'oooooooooosername',
            test: '123',
            test2: '1234',
          });

        nock('https://example.com')
          .get('/.well-known/openid-configuration/jwks')
          .reply(200, { keys: [createdIdToken.key] });

        const cookies = {};

        const oldTime = now();
        await setSessionCookieValue(cookies, {
          session: {
            user: { sub: createdIdToken.sub },
            authorizedScopes: 'openid abc',
            accessTokens: [
              {
                scopes: 'openid abc',
                requestedScopes: 'openid abc',
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
          idTokenSigningAlg: 'ES256',
          refetchUserInfo: true,
        });

        const newFrozenTime = frozenTimeMs + 2000;
        travel(newFrozenTime);

        const tokens = await instance.getTokens(req, res, {
          forceRefresh: true,
        });

        expect(tokens).toEqual({
          accessToken: 'at1',
          scopes: 'openid abc',
          requestedScopes: 'openid abc',
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
              test: '123',
              test2: '1234',
            },
            authorizedScopes: 'openid abc',
            accessTokens: [
              {
                scopes: 'openid abc',
                requestedScopes: 'openid abc',
                accessToken: 'at1',
                accessTokenExpiration: expect.any(Number),
              },
            ],
            idToken: createdIdToken.idToken,
            refreshToken: 'rt1',
          },
          lifetime: { c: oldTime, e: oldTime + 86400, u: now() },
        });
      });

      it('should save with the old refresh token if the updated token response does not have one', async () => {
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
            id_token: createdIdToken.idToken,
            scope: 'something',
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
                scopes: 'abc',
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
          idTokenSigningAlg: 'ES256',
          userInfo: false,
        });

        const newFrozenTime = frozenTimeMs + 2000;
        travel(newFrozenTime);

        const tokens = await instance.getTokens(req, res, {
          forceRefresh: true,
        });

        expect(tokens).toEqual({
          accessToken: 'at1',
          scopes: 'something',
          accessTokenExpiration: expect.any(Number),
          idToken: createdIdToken.idToken,
          refreshToken: 'rt',
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
                scopes: 'something',
                accessToken: 'at1',
                accessTokenExpiration: expect.any(Number),
              },
            ],
            idToken: createdIdToken.idToken,
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, e: oldTime + 86400, u: now() },
        });
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

    describe('isUserInGroup()', () => {
      it('should return false when the session does not have a user', async () => {
        const cookies = {};

        const req = new TestReq({ cookies });
        const res = new TestRes();

        const instance = getConfiguredInstance();

        const result = await instance.isUserInGroup(req, res, ['group1']);

        expect(result).toBe(false);
      });

      it('should return true when the expected groups are empty and session is present', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: { user: { sub: 'id' } },
          lifetime: { u: now(), e: now() + 4, c: now() },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes();

        const instance = getConfiguredInstance();

        const result = await instance.isUserInGroup(req, res, []);

        expect(result).toBe(true);
      });

      it.each([{}, 'groups', 12345678, true, false, null])(
        'should return false when the user groups claim is not a json array',
        async (groups: any) => {
          const cookies = {};

          await setSessionCookieValue(cookies, {
            session: { user: { sub: 'sun', groups } },
            lifetime: { u: now(), e: now() + 4, c: now() },
          });

          const req = new TestReq({ cookies });
          const res = new TestRes();

          const instance = getConfiguredInstance();

          const result = await instance.isUserInGroup(req, res, ['group1']);
          expect(result).toBe(false);
        }
      );

      it('should return true when the expected groups is not an array', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: { user: { sub: 'sun' } },
          lifetime: { u: now(), e: now() + 4, c: now() },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes();

        const instance = getConfiguredInstance();

        const result = await instance.isUserInGroup(
          req,
          res,
          {} as unknown as string[]
        );
        expect(result).toBe(true);
      });

      it('should be able to take in custom groups claim name', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: { user: { sub: 'sun', custom_groups: ['test'] } },
          lifetime: { u: now(), e: now() + 4, c: now() },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes();

        const instance = getConfiguredInstance();

        const result = await instance.isUserInGroup(
          req,
          res,
          ['test'],
          'custom_groups'
        );
        expect(result).toBe(true);
      });

      it.each([
        [[], ['test'], false, false],
        [undefined, ['test'], false, false],
        [['test'], ['test'], true, false],
        [['test'], ['test', 'test_2'], true, false],
        [['test '], ['test'], false, false],
        [
          ['2c17c510-ba14-43d5-a1cf-4bf9bd0523b8'],
          ['2c17c510-ba14-43d5-a1cf-4bf9bd0523b8'],
          true,
          false,
        ],
        [
          [{ id: '2c17c510-ba14-43d5-a1cf-4bf9bd0523b8', name: 'test' }],
          ['2c17c510-ba14-43d5-a1cf-4bf9bd0523b8'],
          true,
          false,
        ],
        [
          [{ id: '2c17c510-ba14-43d5-a1cf-4bf9bd0523b8', name: 'test' }],
          ['test'],
          true,
          false,
        ],
        [['group1', 'group2'], ['group1', 'group3'], false, true],
        [['group1', 'group2'], ['group1', 'group2'], true, true],
        [['group1', 'group2', 'group3'], ['group1', 'group2'], true, true],
      ])(
        'should return expected result',
        async (
          userGroups: any,
          expectedGroups: string[],
          expectedResult: boolean,
          shouldMatchAll: boolean
        ) => {
          const cookies = {};

          await setSessionCookieValue(cookies, {
            session: { user: { sub: 'sun', groups: userGroups } },
            lifetime: { u: now(), e: now() + 4, c: now() },
          });

          const req = new TestReq({ cookies });
          const res = new TestRes();

          const instance = getConfiguredInstance();
          const result = await instance.isUserInGroup(
            req,
            res,
            expectedGroups,
            undefined,
            shouldMatchAll
          );

          expect(result).toBe(expectedResult);
        }
      );
    });
  });
});
