/* eslint-disable import/no-extraneous-dependencies */
import { NextFetchEvent, NextRequest } from 'next/server';
import { describe, beforeEach, afterEach, test, it, expect } from 'vitest';
import { MonoCloudNextClient } from '../src';
import { setupOp, tokenAndUserInfoEnabled } from './op-helpers.js';
import {
  TestAppRes,
  defaultStateCookieValue,
  setSessionCookie,
  setStateCookie,
} from './common-helper';

describe('Base Path', () => {
  let monoCloud: MonoCloudNextClient;

  const defaultEvent = (): any => ({}) as NextFetchEvent;

  beforeEach(() => {
    process.env.MONOCLOUD_AUTH_APP_URL = 'https://example.org/basepath';
    monoCloud = new MonoCloudNextClient();
  });

  afterEach(() => {
    process.env.MONOCLOUD_AUTH_APP_URL = undefined;
  });

  test('should have the base path in redirect uri', async () => {
    setupOp();

    const middleware = monoCloud.authMiddleware();

    const request = new NextRequest(
      new URL('http://localhost:3000/api/auth/signin')
    );

    const serverResponse = await middleware(request, defaultEvent());

    const res = new TestAppRes(serverResponse);

    expect(res.status).toBe(302);
    expect(res.locationHeader.query.redirect_uri).toBe(
      'https://example.org/basepath/api/auth/callback'
    );
  });

  it('should redirect to app url with base path after callback', async () => {
    await setupOp(
      undefined,
      tokenAndUserInfoEnabled,
      {},
      'https://example.org/basepath/api/auth/callback'
    );

    const request = new NextRequest(
      'http://localhost:3000/api/auth/callback?state=state&nonce=nonce&code=code'
    );

    await setStateCookie(request);

    const middleware = monoCloud.authMiddleware();

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.locationHeaderPathOnly).toBe('https://example.org/basepath');
  });

  it('should have base path in return url when set through query from signin after callback', async () => {
    await setupOp(
      undefined,
      tokenAndUserInfoEnabled,
      {},
      'https://example.org/basepath/api/auth/callback'
    );

    const request = new NextRequest(
      `http://localhost:3000/api/auth/callback?state=state&nonce=state&code=code`
    );

    await setStateCookie(request, '', {
      ...defaultStateCookieValue,
      returnUrl: encodeURIComponent('/custom'),
    });

    const middleware = monoCloud.authMiddleware();

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.locationHeaderPathOnly).toBe(
      'https://example.org/basepath/custom'
    );
  });

  it('should remove the session and redirect to authorization server (with base path in post logout uri)', async () => {
    await setupOp(
      undefined,
      tokenAndUserInfoEnabled,
      {},
      'https://example.org/basepath/api/auth/callback'
    );

    const request = new NextRequest('http://localhost:3000/api/auth/signout');

    await setSessionCookie(request);

    const middleware = monoCloud.authMiddleware();

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.locationHeaderPathOnly).toBe(
      'https://op.example.com/connect/endsession'
    );
    expect(res.locationHeader.query).toEqual({
      post_logout_redirect_uri: 'https://example.org/basepath',
      id_token_hint: 'idtoken',
      client_id: '__test_client_id__',
    });
    expect(res.sessionCookie.value).toBeUndefined();
    expect(res.sessionCookie.options.expires).toEqual(new Date(0));
  });

  ['/something', 'https://example.org/basepath/something'].forEach(url => {
    it('should assign the post_logout_redirect_uri from the query (with base path)', async () => {
      await setupOp(
        undefined,
        tokenAndUserInfoEnabled,
        {},
        'https://example.org/basepath/api/auth/callback'
      );

      const request = new NextRequest(
        `http://localhost:3000/api/auth/signout?post_logout_url=${url}`
      );

      await setSessionCookie(request);

      const middleware = monoCloud.authMiddleware();

      const response = await middleware(request, defaultEvent());

      const res = new TestAppRes(response);

      expect(res.locationHeaderPathOnly).toBe(
        'https://op.example.com/connect/endsession'
      );
      expect(res.locationHeader.query).toEqual({
        post_logout_redirect_uri: 'https://example.org/basepath/something',
        id_token_hint: 'idtoken',
        client_id: '__test_client_id__',
      });
      expect(res.sessionCookie.value).toBeUndefined();
      expect(res.sessionCookie.options.expires).toEqual(new Date(0));
    });
  });

  it('should redirect to app url with base path if there is no session', async () => {
    await setupOp(
      undefined,
      tokenAndUserInfoEnabled,
      {},
      'https://example.org/basepath/api/auth/callback'
    );

    const request = new NextRequest('http://localhost:3000/api/auth/signout');

    const middleware = monoCloud.authMiddleware();

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.locationHeaderPathOnly).toBe('https://example.org/basepath');
    expect(res.sessionCookie.value).toBeUndefined();
  });
});
