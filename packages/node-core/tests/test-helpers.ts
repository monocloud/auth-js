/* eslint-disable @typescript-eslint/consistent-indexed-object-style */
import * as jose from 'jose';
import { SerializeOptions } from 'cookie';
import { encrypt } from '@monocloud/auth-core/utils';
import { now } from '@monocloud/auth-core/internal';
import { MonoCloudOptions, MonoCloudRequest, MonoCloudResponse } from '../src';
import { MonoCloudSessionStore, SessionLifetime } from '../src/types';
import type { MonoCloudSession } from '@monocloud/auth-core';

interface MockCookies {
  [key: string]: { value: string; options: SerializeOptions };
}

interface MockQuery {
  [key: string]: string | string[] | undefined;
}

interface MockRequest {
  cookies?: MockCookies;
  query?: MockQuery;
  method?: 'GET' | 'POST';
  url?: string;
  body?: any;
}

interface MockResponse {
  cookies: MockCookies;
  redirectedUrl?: string;
  statusCode?: number;
  body?: any;
  done?: boolean;
  noCacheSet?: boolean;
}

export class TestRes implements MonoCloudResponse {
  public get cookies(): MockCookies {
    return this.res.cookies;
  }

  public readonly res: MockResponse;

  constructor(cookies?: MockCookies) {
    this.res = { cookies: cookies ?? {} };
  }

  internalServerError(): void {
    this.throwIfDone();
    this.res.statusCode = 500;
  }

  redirect(url: string, statusCode?: number): void {
    this.throwIfDone();
    this.res.redirectedUrl = url;
    this.res.statusCode = statusCode;
  }

  sendJson(data: any, statusCode?: number): void {
    this.throwIfDone();
    this.res.statusCode = statusCode;
    this.res.body = data;
  }

  notFound(): void {
    this.throwIfDone();
    this.res.statusCode = 404;
  }

  noContent(): void {
    this.throwIfDone();
    this.res.statusCode = 204;
  }

  methodNotAllowed(): void {
    this.throwIfDone();
    this.res.statusCode = 405;
  }

  setNoCache(): void {
    this.throwIfDone();
    this.res.noCacheSet = true;
  }

  done(): void {
    this.throwIfDone();
    this.res.done = true;
  }

  setCookie(
    cookieName: string,
    value: string,
    options: SerializeOptions
  ): Promise<void> {
    this.throwIfDone();
    this.cookies[cookieName] = { value, options };
    return Promise.resolve();
  }

  private throwIfDone(): void {
    if (this.res.done) {
      throw new Error('ERR: Called done twice in TestRes');
    }
  }
}

export class TestReq implements MonoCloudRequest {
  public get cookies(): MockCookies | undefined {
    return this.req.cookies;
  }

  public readonly req: MockRequest;

  constructor(req?: Partial<MockRequest>) {
    this.req = {
      cookies: req?.cookies ?? {},
      query: req?.query ?? {},
      url: req?.url,
      body: req?.body,
      method: req?.method,
    };
  }

  getRoute(_parameter: string): string | string[] | undefined {
    throw new Error('Method not implemented.');
  }

  getQuery(parameter: string): string | string[] | undefined {
    if (this.req.url) {
      const url = new URL(this.req.url);
      return url.searchParams.get(parameter) ?? undefined;
    }
    return this.req.query?.[parameter];
  }

  getRawRequest(): Promise<{
    method: string;
    url: string;
    /* eslint-disable @typescript-eslint/no-non-null-assertion */
    body: string | Record<string, string>;
  }> {
    return Promise.resolve({
      method: this.req.method!,
      body: this.req.body!,
      url: this.req.url!,
    });
  }

  getCookie(name: string): Promise<string | undefined> {
    return Promise.resolve(this.cookies?.[name]?.value);
  }

  getAllCookies(): Promise<Map<string, string>> {
    const map = new Map();
    Object.keys(this.cookies ?? {}).forEach(key =>
      map.set(key, this.cookies?.[key].value)
    );
    return Promise.resolve(map);
  }
}

export class TestStore implements MonoCloudSessionStore {
  private store = new Map<string, MonoCloudSession>();

  lifetimes = new Map<string, SessionLifetime>();

  get(key: string): Promise<MonoCloudSession | null | undefined> {
    return Promise.resolve(this.store.get(key));
  }

  set(
    key: string,
    data: MonoCloudSession,
    lifetime: SessionLifetime
  ): Promise<void> {
    this.store.set(key, JSON.parse(JSON.stringify(data)));
    this.lifetimes.set(key, JSON.parse(JSON.stringify(lifetime)));
    return Promise.resolve();
  }

  delete(key: string): Promise<void> {
    this.store.delete(key);
    this.lifetimes.delete(key);
    return Promise.resolve();
  }
}

export const defaultConfig: Partial<MonoCloudOptions> = {
  cookieSecret: '__test_session_secret__',
  clientId: '__test_client_id__',
  clientSecret: '__test_client_secret__',
  tenantDomain: 'https://example.com',
  appUrl: 'https://example.org',
  userInfo: false,
  allowQueryParamOverrides: true,
  defaultAuthParams: {
    responseType: 'code',
    scopes: 'openid profile read:customer',
  },
};

export const defaultStoreKeyForTest = 'key';

export const defaultSessionData = (): MonoCloudSession => ({
  user: {
    sub: 'randomid',
  },
  foo: 'bar',
  accessToken: 'at',
  accessTokenExpiration: 0,
  idToken: 'idt',
  refreshToken: 'rt',
  scopes: 'openid',
});

export const getSessionCookie = (params?: {
  session?: any;
  store?: MonoCloudSessionStore;
  key?: any;
  exp?: number;
}): Promise<string> => {
  const lifetime = { e: params?.exp ?? now() + 1, c: now(), u: now() };

  const cookieValue = {
    key: params?.key ?? defaultStoreKeyForTest,
    lifetime,
    session: !params?.store ? params?.session : undefined,
  };

  if (params?.store) {
    void params.store
      .set(cookieValue.key, params?.session ?? {}, lifetime)
      .then()
      .catch();
  }

  return encrypt(JSON.stringify(cookieValue), defaultConfig.cookieSecret!);
};

export const createTestIdToken = async (
  claims = {}
): Promise<{ idToken: string; key: jose.JWK; sub: string }> => {
  const kp = await jose.generateKeyPair('ES256', { extractable: true });
  const jwk = await jose.exportJWK(kp.publicKey);
  const sub = await jose.calculateJwkThumbprint(jwk);
  return {
    idToken: await new jose.SignJWT({
      sub_jwk: jwk,
      sub,
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
