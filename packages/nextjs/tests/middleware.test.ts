/* eslint-disable import/no-extraneous-dependencies */
import { NextRequest, NextResponse } from 'next/server';
import { beforeEach, describe, expect, it } from 'vitest';
import { NextFetchEvent } from 'next/dist/server/web/spec-extension/fetch-event';
import { MonoCloudNextClient } from '../src';
import {
  defaultSessionCookieValue,
  defaultStateCookieValue,
  getCookieValue,
  setSessionCookie,
  setStateCookie,
  TestAppRes,
  userWithGroupsSessionCookieValue,
} from './common-helper';
import {
  defaultAppUserInfoResponse,
  defaultDiscovery,
  noBodyDiscoverySuccess,
  noTokenAndUserInfo,
  setupOp,
} from './op-helpers.js';

describe('MonoCloud Middleware', () => {
  let monoCloud: MonoCloudNextClient;
  const defaultEvent = (): any => ({}) as NextFetchEvent;
  beforeEach(() => {
    monoCloud = new MonoCloudNextClient();
  });

  it('should redirect unauthenticated requests to signin endpoint', async () => {
    const middleware = monoCloud.authMiddleware();

    const request = new NextRequest('http://localhost:3000/');

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toBe(307);
    expect(res.locationHeaderPathOnly).toBe(
      'https://example.org/api/auth/signin'
    );
  });

  it('should return forbidden for requests with x-middleware-subrequest header', async () => {
    const middleware = monoCloud.authMiddleware();

    const request = new NextRequest('http://localhost:3000/');

    request.headers.set('x-middleware-subrequest', 'anyvalue');

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toBe(403);
  });

  [
    NextResponse.json({ custom: true }),
    { body: '{"custom":true}', status: 200 },
  ].forEach((ret: any, i) => {
    it(`can customize onAccessDenied for unauthenticated requests ${i + 1}/2`, async () => {
      const middleware = monoCloud.authMiddleware({
        onAccessDenied: () => ret,
      });

      const request = new NextRequest('http://localhost:3000/');

      const response = await middleware(request, defaultEvent());

      const res = new TestAppRes(response);

      expect(res.status).toBe(200);
      expect(await res.getBody()).toStrictEqual({ custom: true });
    });
  });

  it('will continue the request if onAccessDenied returns falsy', async () => {
    const middleware = monoCloud.authMiddleware({
      onAccessDenied: () => null,
    });

    const request = new NextRequest('http://localhost:3000/');

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toEqual(200);
  });

  it('should return 401 unauthorized for api requests', async () => {
    const middleware = monoCloud.authMiddleware();

    const request = new NextRequest('http://localhost:3000/api/something');

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toBe(401);
    expect(await res.getBody()).toEqual({ message: 'unauthorized' });
  });

  it('should retain the path as return_url in the signin redirect', async () => {
    const middleware = monoCloud.authMiddleware();

    const request = new NextRequest('http://localhost:3000/path?any=thing');

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.locationHeaderPathOnly).toBe(
      'https://example.org/api/auth/signin'
    );
    expect(res.locationHeader.query).toEqual({
      return_url: '/path?any=thing',
    });
  });

  it('can customize the protected routes', async () => {
    const middleware = monoCloud.authMiddleware({
      protectedRoutes: ['/protected'],
    });

    const skippedRequest = new NextRequest('http://localhost:3000/skipped');
    const skippedResponse = await middleware(skippedRequest, defaultEvent());
    const skippedRes = new TestAppRes(skippedResponse);
    expect(skippedRes.status).not.toBe(307);

    const protectedRequest = new NextRequest('http://localhost:3000/protected');
    const protectedResponse = await middleware(
      protectedRequest,
      defaultEvent()
    );
    const protectedRes = new TestAppRes(protectedResponse);
    expect(protectedRes.status).toBe(307);
  });

  ['/protected', '/secret', '/protected/nested', '/secret/nested'].forEach(
    endpoint => {
      it('can protect routes using regex', async () => {
        const middleware = monoCloud.authMiddleware({
          protectedRoutes: ['^/(protected|secret)'],
        });

        const skippedRequest = new NextRequest('http://localhost:3000/skipped');
        const skippedResponse = await middleware(
          skippedRequest,
          defaultEvent()
        );
        const skippedRes = new TestAppRes(skippedResponse);
        expect(skippedRes.status).not.toBe(307);

        const protectedRequest = new NextRequest(
          `http://localhost:3000${endpoint}`
        );
        const protectedResponse = await middleware(
          protectedRequest,
          defaultEvent()
        );
        const protectedRes = new TestAppRes(protectedResponse);
        expect(protectedRes.status).toBe(307);
      });
    }
  );

  it('can take in a callback that can decide if the route is protected', async () => {
    const middleware = monoCloud.authMiddleware({
      protectedRoutes: req => {
        return req.nextUrl.pathname.includes('/protected');
      },
    });

    const skippedRequest = new NextRequest('http://localhost:3000/skipped');
    const skippedResponse = await middleware(skippedRequest, defaultEvent());
    const skippedRes = new TestAppRes(skippedResponse);
    expect(skippedRes.status).not.toBe(307);

    const protectedRequest = new NextRequest(
      'http://localhost:3000/something/protected'
    );
    const protectedResponse = await middleware(
      protectedRequest,
      defaultEvent()
    );
    const protectedRes = new TestAppRes(protectedResponse);
    expect(protectedRes.status).toBe(307);
    expect(protectedRes.locationHeaderPathOnly).toBe(
      'https://example.org/api/auth/signin'
    );
  });

  it('should allow authenticated users', async () => {
    const middleware = monoCloud.authMiddleware();

    const request = new NextRequest('http://localhost:3000/test');

    await setSessionCookie(request);

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).not.toBe(307);
  });

  it('can return authMiddleware from a customMiddleware', async () => {
    const customMiddleware = async (
      req: NextRequest,
      evt: NextFetchEvent
      // eslint-disable-next-line require-await
    ): Promise<any> => {
      return monoCloud.authMiddleware(req, evt);
    };

    const request = new NextRequest('http://localhost:3000/test');

    const response = await customMiddleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toBe(307);
    expect(res.locationHeaderPathOnly).toBe(
      'https://example.org/api/auth/signin'
    );
  });

  it('returns forbidden if the user does not belong to a group (Non API)', async () => {
    const middleware = monoCloud.authMiddleware({
      protectedRoutes: [{ routes: ['/protected'], groups: ['NOPE'] }],
    });

    const request = new NextRequest('http://localhost:3000/protected');

    await setSessionCookie(
      request,
      undefined,
      userWithGroupsSessionCookieValue
    );

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toBe(403);
    expect(await res.getBody()).toBe('forbidden');
  });

  it('succeeds if the request is a non-group protected route', async () => {
    const middleware = monoCloud.authMiddleware({
      protectedRoutes: [{ routes: ['/protected'], groups: ['test'] }],
    });

    const request = new NextRequest('http://localhost:3000/hello');

    await setSessionCookie(
      request,
      undefined,
      userWithGroupsSessionCookieValue
    );

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).not.toBe(403);
  });

  it('returns forbidden if the user does not belong to a group (API)', async () => {
    const middleware = monoCloud.authMiddleware({
      protectedRoutes: [{ routes: ['/api/protected'], groups: ['NOPE'] }],
    });

    const request = new NextRequest('http://localhost:3000/api/protected');

    await setSessionCookie(
      request,
      undefined,
      userWithGroupsSessionCookieValue
    );

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toBe(403);
    expect(await res.getBody()).toStrictEqual({ message: 'forbidden' });
  });

  it('allows the user if the user belongs to the group', async () => {
    const middleware = monoCloud.authMiddleware({
      protectedRoutes: [{ routes: ['/protected'], groups: ['test'] }],
    });

    const request = new NextRequest('http://localhost:3000/protected');

    await setSessionCookie(
      request,
      undefined,
      userWithGroupsSessionCookieValue
    );

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toBe(200);
  });

  it('can set custom groups claim', async () => {
    const middleware = monoCloud.authMiddleware({
      groupsClaim: 'CUSTOM_GROUPS',
      protectedRoutes: [{ routes: ['/protected'], groups: ['test'] }],
    });

    const request = new NextRequest('http://localhost:3000/protected');

    await setSessionCookie(request, undefined, {
      ...defaultSessionCookieValue,
      user: { ...defaultSessionCookieValue.user, CUSTOM_GROUPS: ['test'] },
    });

    const response = await middleware(request, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toBe(200);
  });

  [
    {
      ret: { body: '{"custom":true}', status: 200 },
      expected: { custom: true },
      route: '/protected',
    },
    {
      ret: NextResponse.json({ custom: true }),
      expected: { custom: true },
      route: '/protected',
    },
    {
      ret: null,
      expected: '',
      route: '/protected',
    },
  ].forEach(({ ret, expected, route }, i) => {
    it(`can set custom onAccessDenied middleware function ${i + 1}/1`, async () => {
      const middleware = monoCloud.authMiddleware({
        protectedRoutes: [
          {
            routes: [route],
            groups: ['NOPE'],
          },
        ],
        onAccessDenied: () => ret as any,
      });

      const request = new NextRequest(`http://localhost:3000${route}`);

      await setSessionCookie(
        request,
        undefined,
        userWithGroupsSessionCookieValue
      );

      const response = await middleware(request, defaultEvent());

      const res = new TestAppRes(response);

      expect(res.status).toBe(200);
      expect(await res.getBody()).toStrictEqual(expected);
    });
  });

  it('can pass onError to authMiddleware() to handle errors', async () => {
    const middleware = monoCloud.authMiddleware({
      onError: () => Promise.resolve(NextResponse.json({ custom: true })),
    });

    const req = new NextRequest(
      'http://localhost:3000/api/auth/callback?code=123&state=321'
    );

    const response = await middleware(req, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toBe(200);
    expect(await res.getBody()).toEqual({ custom: true });
  });

  it('userinfo endpoint should return 500 for authorization server errors', async () => {
    await setupOp(noBodyDiscoverySuccess, noTokenAndUserInfo);

    monoCloud = new MonoCloudNextClient({ refetchUserInfo: true });

    const middleware = monoCloud.authMiddleware();

    const req = new NextRequest('http://localhost:3000/api/auth/userinfo');

    await setSessionCookie(req);

    const response = await middleware(req, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toBe(500);
  });

  it('should return 500 for unexpected errors', async () => {
    await setupOp(defaultDiscovery, noTokenAndUserInfo);

    const middleware = monoCloud.authMiddleware();

    const req = new NextRequest(
      new URL(
        'http://localhost:3000/api/auth/callback?error=foo&error_description=bar&state=foo'
      )
    );

    const response = await middleware(req, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toBe(500);
  });

  it('callback endpoint should return 500 for authorization server errors', async () => {
    await setupOp(noBodyDiscoverySuccess, noTokenAndUserInfo);

    const req = new NextRequest(
      'http://localhost:3000/api/auth/callback?state=state&nonce=nonce&code=code'
    );

    await setStateCookie(req);

    const middleware = monoCloud.authMiddleware();

    const response = await middleware(req, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toBe(500);
  });

  it('should return 401 for unknown routes', async () => {
    const middleware = monoCloud.authMiddleware();

    const response = await middleware(
      new NextRequest(new URL('http://localhost:3000/api/auth/unknown')),
      defaultEvent()
    );

    const res = new TestAppRes(response);

    expect(res.status).toBe(401);
  });

  [
    [['DELETE', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'HEAD'], '/api/auth/signin'],
    [['DELETE', 'OPTIONS', 'PUT', 'PATCH', 'HEAD'], '/api/auth/callback'],
    [
      ['DELETE', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'HEAD'],
      '/api/auth/userinfo',
    ],
    [
      ['DELETE', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'HEAD'],
      '/api/auth/signout',
    ],
  ].forEach(([methods, endpoint]) => {
    (methods as string[]).forEach(method => {
      it(`should return 405 on ${endpoint} for request type ${method}`, async () => {
        await setupOp(defaultDiscovery, noTokenAndUserInfo);

        const middleware = monoCloud.authMiddleware();

        const response = await middleware(
          new NextRequest(new URL(`http://localhost:3000${endpoint}`), {
            method,
          }),
          defaultEvent()
        );

        const res = new TestAppRes(response);

        expect(res.status).toBe(405);
      });
    });
  });

  it('should redirect to app url after callback', async () => {
    await setupOp();

    const middleware = monoCloud.authMiddleware();

    const req = new NextRequest(
      'http://localhost:3000/api/auth/callback?state=state&nonce=nonce&code=code'
    );

    await setStateCookie(req);

    const response = await middleware(req, defaultEvent());

    const res = new TestAppRes(response);

    const userInfoReq = new NextRequest(
      'http://localhost:3000/api/auth/userinfo'
    );

    userInfoReq.cookies.set('session', res.sessionCookie.value ?? '');

    const userInfoResponse = await middleware(userInfoReq, defaultEvent());
    const userInfoRes = new TestAppRes(userInfoResponse);

    expect(res.locationHeaderPathOnly).toBe('https://example.org/');
    expect(res.sessionCookie.value?.trim().length).toBeGreaterThan(1);

    expect(await userInfoRes.getBody()).toMatchObject(
      defaultAppUserInfoResponse
    );
  });

  it('should process a post request', async () => {
    await setupOp();

    const middleware = monoCloud.authMiddleware();

    const headers = new Headers();
    headers.set('content-type', 'application/x-www-form-urlencoded');

    const rawReq = new Request('http://localhost:3000/api/auth/callback', {
      method: 'POST',
      body: 'state=state&nonce=nonce&code=code',
      headers,
    });

    const req = new NextRequest(rawReq);

    await setStateCookie(req);

    const response = await middleware(req, defaultEvent());

    const res = new TestAppRes(response);

    const userInfoReq = new NextRequest(
      'http://localhost:3000/api/auth/userinfo'
    );

    userInfoReq.cookies.set('session', res.sessionCookie.value ?? '');

    const userInfoResponse = await middleware(userInfoReq, defaultEvent());
    const userInfoRes = new TestAppRes(userInfoResponse);

    expect(res.locationHeaderPathOnly).toBe('https://example.org/');
    expect(res.sessionCookie.value?.trim().length).toBeGreaterThan(1);

    expect(await userInfoRes.getBody()).toMatchObject(
      defaultAppUserInfoResponse
    );
  });

  // refer test: 'should set the custom return url in the state' in sigin in handler
  it('should redirect to return url set through query from signin after callback', async () => {
    await setupOp();

    const middleware = monoCloud.authMiddleware();

    const req = new NextRequest(
      `http://localhost:3000/api/auth/callback?state=state&nonce=state&code=code`
    );

    await setStateCookie(req, '', {
      ...defaultStateCookieValue,
      returnUrl: encodeURIComponent('/custom'),
    });

    const response = await middleware(req, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.locationHeaderPathOnly).toBe('https://example.org/custom');
  });

  it('should redirect to authorize endpoint when custom signin route is called', async () => {
    await setupOp();

    monoCloud = new MonoCloudNextClient({
      routes: {
        signIn: '/api/auth/custom_login',
      },
    });

    const middleware = monoCloud.authMiddleware();

    const req = new NextRequest(
      new URL('http://localhost:3000/api/auth/custom_login')
    );

    const serverResponse = await middleware(req, defaultEvent());

    const res = new TestAppRes(serverResponse);

    expect(res.status).toBe(302);
    expect(res.locationHeaderPathOnly).toBe(
      'https://op.example.com/connect/authorize'
    );
  });

  it('should redirect to authorize endpoint', async () => {
    await setupOp(defaultDiscovery, noTokenAndUserInfo);

    const middleware = monoCloud.authMiddleware();

    const serverResponse = await middleware(
      new NextRequest(new URL('http://localhost:3000/api/auth/signin')),
      defaultEvent()
    );

    const res = new TestAppRes(serverResponse);

    expect(res.status).toBe(302);
    expect(res.locationHeaderPathOnly).toBe(
      'https://op.example.com/connect/authorize'
    );
    expect(res.locationHeader.query).toEqual({
      client_id: '__test_client_id__',
      scope: 'openid profile email read:customer',
      response_type: 'code',
      redirect_uri: 'https://example.org/api/auth/callback',
      nonce: expect.any(String),
      state: expect.any(String),
      code_challenge: expect.any(String),
      code_challenge_method: 'S256',
    });
  });

  it('prompt=create in query should redirect to authorize endpoint with prompt=create', async () => {
    await setupOp(defaultDiscovery, noTokenAndUserInfo);

    const middleware = monoCloud.authMiddleware();

    const serverResponse = await middleware(
      new NextRequest(
        new URL('http://localhost:3000/api/auth/signin?prompt=create')
      ),
      defaultEvent()
    );

    const res = new TestAppRes(serverResponse);

    expect(res.status).toBe(302);
    expect(res.locationHeaderPathOnly).toBe(
      'https://op.example.com/connect/authorize'
    );
    expect(res.locationHeader.query.prompt).toBe('create');
  });

  it('custom login_hint in query should redirect to authorize endpoint with login_hint', async () => {
    await setupOp(defaultDiscovery, noTokenAndUserInfo);

    const middleware = monoCloud.authMiddleware();

    const serverResponse = await middleware(
      new NextRequest(
        new URL('http://localhost:3000/api/auth/signin?login_hint=username')
      ),
      defaultEvent()
    );

    const res = new TestAppRes(serverResponse);

    expect(res.status).toBe(302);
    expect(res.locationHeaderPathOnly).toBe(
      'https://op.example.com/connect/authorize'
    );
    expect(res.locationHeader.query.login_hint).toBe('username');
  });

  it('custom authenticator in query should redirect to authorize endpoint with authenticator in the authenticator_hint', async () => {
    await setupOp(defaultDiscovery, noTokenAndUserInfo);

    const middleware = monoCloud.authMiddleware();

    const serverResponse = await middleware(
      new NextRequest(
        new URL(
          'http://localhost:3000/api/auth/signin?authenticator_hint=google'
        )
      ),
      defaultEvent()
    );

    const res = new TestAppRes(serverResponse);

    expect(res.status).toBe(302);
    expect(res.locationHeaderPathOnly).toBe(
      'https://op.example.com/connect/authorize'
    );
    expect(res.locationHeader.query.authenticator_hint).toBe('google');
  });

  it('should set the state cookie', async () => {
    await setupOp(defaultDiscovery, noTokenAndUserInfo);

    const middleware = monoCloud.authMiddleware();

    const serverResponse = await middleware(
      new NextRequest(new URL('http://localhost:3000/api/auth/signin')),
      defaultEvent()
    );

    const res = new TestAppRes(serverResponse);

    const { value, options } = res.stateCookie;

    expect(value?.trim().length).toBeGreaterThan(0);
    expect(options).toEqual({
      path: '/',
      sameSite: 'lax',
      secure: true,
      httpOnly: true,
      domain: 'localhost',
      expires: 'Infinity',
    });
  });

  it('should set the custom return url in the state', async () => {
    await setupOp(defaultDiscovery, noTokenAndUserInfo);

    const middleware = monoCloud.authMiddleware();

    const serverResponse = await middleware(
      new NextRequest(
        new URL('http://localhost:3000/api/auth/signin?return_url=/custom')
      ),
      defaultEvent()
    );

    const res = new TestAppRes(serverResponse);

    const {
      authState: { returnUrl },
    } = await getCookieValue(res.stateCookie.value ?? '');

    expect(returnUrl).toBe(encodeURIComponent('/custom'));
  });

  it('should remove the session and redirect to authorization server', async () => {
    await setupOp();

    const req = new NextRequest('http://localhost:3000/api/auth/signout');

    await setSessionCookie(req);

    const middleware = monoCloud.authMiddleware();

    const response = await middleware(req, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.locationHeaderPathOnly).toBe(
      'https://op.example.com/connect/endsession'
    );
    expect(res.locationHeader.query).toEqual({
      post_logout_redirect_uri: 'https://example.org',
      id_token_hint: 'idtoken',
      client_id: '__test_client_id__',
    });
    expect(res.sessionCookie.value).toBeUndefined();
    expect(res.sessionCookie.options.expires).toEqual(new Date(0));
  });

  ['/something', 'https://example.org/something'].forEach(url => {
    it('should assign the post_logout_redirect_uri from the query', async () => {
      await setupOp();

      const req = new NextRequest(
        `http://localhost:3000/api/auth/signout?post_logout_url=${url}`
      );

      await setSessionCookie(req);

      const middleware = monoCloud.authMiddleware();

      const response = await middleware(req, defaultEvent());

      const res = new TestAppRes(response);

      expect(res.locationHeaderPathOnly).toBe(
        'https://op.example.com/connect/endsession'
      );
      expect(res.locationHeader.query).toEqual({
        post_logout_redirect_uri: 'https://example.org/something',
        id_token_hint: 'idtoken',
        client_id: '__test_client_id__',
      });
      expect(res.sessionCookie.value).toBeUndefined();
      expect(res.sessionCookie.options.expires).toEqual(new Date(0));
    });
  });

  it('can redirect to external domains', async () => {
    await setupOp();

    const req = new NextRequest(
      'http://localhost:3000/api/auth/signout?post_logout_url=https://something.com/test'
    );

    await setSessionCookie(req);

    const middleware = monoCloud.authMiddleware();

    const response = await middleware(req, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.locationHeaderPathOnly).toBe(
      'https://op.example.com/connect/endsession'
    );
    expect(res.locationHeader.query).toEqual({
      post_logout_redirect_uri: 'https://something.com/test',
      id_token_hint: 'idtoken',
      client_id: '__test_client_id__',
    });
    expect(res.sessionCookie.value).toBeUndefined();
    expect(res.sessionCookie.options.expires).toEqual(new Date(0));
  });

  it('should redirect to app url if there is no session', async () => {
    await setupOp();

    const req = new NextRequest('http://localhost:3000/api/auth/signout');

    const middleware = monoCloud.authMiddleware();

    const response = await middleware(req, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.locationHeaderPathOnly).toBe('https://example.org/');
    expect(res.sessionCookie.value).toBeUndefined();
  });

  it('should return the current user claims', async () => {
    const middleware = monoCloud.authMiddleware();

    const req = new NextRequest('http://localhost:3000/api/auth/userinfo');

    await setSessionCookie(req, '', {
      ...defaultSessionCookieValue,
      user: { sub: 'marine', noice: 'toit' },
    });

    const response = await middleware(req, defaultEvent());

    const res = new TestAppRes(response);

    expect(await res.getBody()).toEqual({ sub: 'marine', noice: 'toit' });
  });

  it('should return no content if there is no session', async () => {
    const middleware = monoCloud.authMiddleware();

    const req = new NextRequest('http://localhost:3000/api/auth/userinfo');

    const response = await middleware(req, defaultEvent());

    const res = new TestAppRes(response);

    expect(res.status).toBe(204);
  });
});
