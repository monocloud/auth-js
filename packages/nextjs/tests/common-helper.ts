import { CookieJar } from 'tough-cookie';
import { UrlWithParsedQuery, parse } from 'url';
import { NextRequest, NextResponse } from 'next/server';
import type { MonoCloudSession } from '@monocloud/auth-node-core';
import { encrypt, decrypt } from '@monocloud/auth-node-core/utils';

export const now = (): number => Math.floor(Date.now() / 1000);

export const setupDefaultConfig = (): void => {
  process.env.MONOCLOUD_AUTH_TENANT_DOMAIN = 'https://op.example.com';
  process.env.MONOCLOUD_AUTH_CLIENT_ID = '__test_client_id__';
  process.env.MONOCLOUD_AUTH_CLIENT_SECRET = '__test_client_secret__';
  process.env.MONOCLOUD_AUTH_APP_URL = 'https://example.org';
  process.env.MONOCLOUD_AUTH_COOKIE_SECRET = 'cookie_secret';
  process.env.MONOCLOUD_AUTH_SCOPES = 'openid profile email read:customer';
};

export const deleteDefaultConfig = (): void => {
  process.env.MONOCLOUD_AUTH_TENANT_DOMAIN = undefined;
  process.env.MONOCLOUD_AUTH_CLIENT_ID = undefined;
  process.env.MONOCLOUD_AUTH_CLIENT_SECRET = undefined;
  process.env.MONOCLOUD_AUTH_APP_URL = undefined;
  process.env.MONOCLOUD_AUTH_COOKIE_SECRET = undefined;
  process.env.MONOCLOUD_AUTH_SCOPES = undefined;
};

export interface ParsedCookie {
  value: string | undefined;
  options: {
    path?: string | null;
    sameSite?: string;
    secure?: boolean;
    expires?: Date | 'Infinity' | null;
    domain?: string | null;
    httpOnly?: boolean;
  };
}

export interface TestResponse {
  status: number;
  locationHeader: UrlWithParsedQuery;
  locationHeaderPathOnly: string;
  stateCookie: ParsedCookie;
  sessionCookie: ParsedCookie;
  getBody(): Promise<any>;
}

export class TestPageRes implements TestResponse {
  constructor(
    private readonly res: any,
    private readonly data: any,
    private readonly baseUrl: string,
    public readonly cookieJar: CookieJar
  ) {}

  get status(): number {
    return this.res.statusCode;
  }

  get locationHeader(): UrlWithParsedQuery {
    return parse(this.res.headers.location, true);
  }

  get locationHeaderPathOnly(): string {
    const url = this.locationHeader;
    return `${url.protocol}//${url.host}${url.pathname}`;
  }

  get stateCookie(): ParsedCookie {
    const stateCookie = this.cookieJar
      .getCookiesSync(this.baseUrl)
      .find(x => x.key === 'state');

    return {
      value: stateCookie?.value,
      options: {
        path: stateCookie?.path,
        sameSite: stateCookie?.sameSite,
        secure: stateCookie?.secure,
        expires: stateCookie?.expires,
        domain: stateCookie?.domain,
        httpOnly: stateCookie?.httpOnly,
      },
    };
  }

  get sessionCookie(): ParsedCookie {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const sessionCookie = this.cookieJar
      .serializeSync()!
      .cookies.find(x => x.key === 'session') as
      | ({ value: string } & ParsedCookie['options'])
      | undefined;

    return {
      value: sessionCookie?.value,
      options: {
        path: sessionCookie?.path,
        sameSite: sessionCookie?.sameSite,
        secure: sessionCookie?.secure,
        expires:
          sessionCookie?.expires && sessionCookie?.expires !== 'Infinity'
            ? new Date(sessionCookie?.expires)
            : sessionCookie?.expires,
        domain: sessionCookie?.domain,
        httpOnly: sessionCookie?.httpOnly,
      },
    };
  }

  getBody(): Promise<any> {
    try {
      const data = JSON.parse(this.data);
      return Promise.resolve(data);
    } catch {
      return Promise.resolve(this.data);
    }
  }
}

export class TestAppRes implements TestResponse {
  private readonly res: NextResponse;

  constructor(res: any) {
    this.res = res;
  }

  get status(): number {
    return this.res.status;
  }

  get locationHeader(): UrlWithParsedQuery {
    return parse(this.res.headers.get('location') ?? '', true);
  }

  get locationHeaderPathOnly(): string {
    const url = this.locationHeader;
    return `${url.protocol}//${url.host}${url.pathname}`;
  }

  get stateCookie(): ParsedCookie {
    const stateCookie = this.res.cookies.get('state');

    return {
      value: stateCookie?.value,
      options: {
        path: stateCookie?.path,
        sameSite: stateCookie?.sameSite,
        secure: stateCookie?.secure,
        expires: stateCookie?.expires
          ? new Date(stateCookie.expires)
          : 'Infinity',
        domain: stateCookie?.domain ?? 'localhost',
        httpOnly: stateCookie?.httpOnly,
      },
    } as any;
  }

  get sessionCookie(): ParsedCookie {
    const sessionCookie = this.res.cookies.get('session');

    return {
      value: sessionCookie?.value,
      options: {
        path: sessionCookie?.path,
        sameSite: sessionCookie?.sameSite,
        secure: sessionCookie?.secure,
        expires: sessionCookie?.expires
          ? new Date(sessionCookie?.expires)
          : sessionCookie?.expires,
        domain: sessionCookie?.domain ?? 'localhost',
        httpOnly: sessionCookie?.httpOnly,
      },
    } as any;
  }

  async getBody(): Promise<any> {
    let data;
    try {
      data = await this.res.text();
      data = JSON.parse(data);
    } catch {
      // ignore
    }
    return data;
  }
}

export const defaultStateCookieValue = {
  appState: '{}',
  nonce: 'nonce',
  state: 'state',
  codeVerifier: 'a', // ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs
};

export const setStateCookie = async (
  reqOrCookieJar: NextRequest | CookieJar,
  currentUrl = '',
  authState: {
    state: string;
    nonce: string;
    appState: string;
    codeVerifier?: string;
    maxAge?: number;
    returnUrl?: string;
  } = defaultStateCookieValue
): Promise<void> => {
  const value = await encrypt(
    JSON.stringify({ authState }),
    process.env.MONOCLOUD_AUTH_COOKIE_SECRET ?? ''
  );

  if (reqOrCookieJar instanceof CookieJar) {
    reqOrCookieJar.setCookieSync(`state=${value}`, currentUrl);

    return;
  }

  reqOrCookieJar.cookies.set('state', value);
};

export const defaultSessionCookieValue = {
  user: { sub: 'sub' },
  accessTokens: [
    {
      accessToken: 'at',
      accessTokenExpiration: now() + 300,
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      scopes: process.env.MONOCLOUD_AUTH_SCOPES!,
    },
  ],
  idToken: 'idtoken',
  refreshToken: 'rt',
};

export const userWithGroupsSessionCookieValue = {
  ...defaultSessionCookieValue,
  user: { ...defaultSessionCookieValue.user, groups: ['test'] },
};

export const setSessionCookie = async (
  reqOrCookieJar: NextRequest | CookieJar,
  currentUrl = '',
  session: MonoCloudSession = defaultSessionCookieValue,
  lifetime: { u?: number; e?: number; c?: number } = {
    u: now(),
    e: now() + 300,
    c: now(),
  }
): Promise<void> => {
  const value = await encrypt(
    JSON.stringify({
      session,
      lifetime,
    }),
    process.env.MONOCLOUD_AUTH_COOKIE_SECRET ?? ''
  );

  if (reqOrCookieJar instanceof CookieJar) {
    reqOrCookieJar.setCookieSync(`session=${value}`, currentUrl);

    return;
  }

  reqOrCookieJar.cookies.set('session', value);
};

export const getCookieValue = async (data: string): Promise<any> =>
  JSON.parse(
    (await decrypt(data, process.env.MONOCLOUD_AUTH_COOKIE_SECRET ?? '')) ?? ''
  );
