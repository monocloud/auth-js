import * as jose from 'jose';
import { expect, vi } from 'vitest';

export const idTokenPrivateKey = {
  kty: 'RSA',
  alg: 'RS256',
  n: 'rS_iO491_fxo4MEfoxcNVba0Z72XB_wuywPoXgYohSauOyXMZrzpT6qQExn4ev7cwF2qzb2k8rQjYz-2A0FjmCWCnQLfdiAxWBuzlLGJW2-6rPoRhZ16pID_Drd7X8Ra6qXnGcsI5Lwu3kj6UimuflgOiBHw2sJ2bu5HByXDN3gVNDK5mLZJLsnnKkfX13vLrhzScAP75zsaf6eOTuSO_Hbn1A-E8f4f07M3MHDoN_dnoNt4ucPPXJV0MGZv0ZrxPeDxUyiD1Qd4PHXdDiG3uIwW-s605PJ7NigxHm2L0e4vbSzHTVK1VJiF1wgUKD4XtRNguWEfPjN6CQacwgmBfw',
  e: 'AQAB',
  d: 'SEKY6dH_YMR-u_xIZ4N4SGGtnzVfPXEu0v0j6Is4P-o2Oy6XvOwoitl3OMkWwLbzQ34xhJuSpcOcmk4ccvpHBFXuS_XFaCOhgwo34Rw8W_7fzEmgovfkkpvSEAFlhD1I0-v542ywHsQX6B5Z94s1p7i1A3g83wHRaZKY5zYN4GfVNLFogY7VP71_gMb7HeYe855mHONOWBZakpMtv59L1V-lKDds1ULSSrZ_SJG8drStd4plXhg7MHIGGO7Nn_XbjMoBYTPmFxHSflKNczwTmWI-LeIFz4urN8mgwbwUHgoLp0ZsdfuA3YjS4yySfGwlN1oQekItD9bUYHV-UJwjbQ',
  p: '5xJUkmGQcb2Hpca-j8wz9qg4TZ_esdIUwxoYFLcj8mSGOHr5nd5ieyx_upxgYUghktHUPaoJNpClUUvC-xXr7Ub4O2HlYvnC6xVQl0zvIO-huKbkWaAHogxTwkwz9peYeZQusJiTAH4CA3oD69SgRRVbIpXqtC0_pcyiWeTkgr0',
  q: 'v97qBu0U5epZg1sT64ZiZfWCsCgVflQTJdIdkZ4b2YnqgqoQ-4C3X32mVKdEEca63ygIylQi5YWANUo3qm005HSIa7Cy9bBBN8itd_5KDnXDcMiq3IaCCIHxJodlUaudJAy8WdsoK1oP0rjrQflVIUY66QB8Dkw4RKShM2RiVus',
  dp: '3zO0n6VAiq3CPt7IqkxdEXCS2mCIE4pTZdZp1nDFd1mk0R_wyI7M4CAuzUpKSw4K6DBpbJs3xQ5ZsjqVgEY_m_aGx42br0yE_OGc9FlrT4xJ0fzb7LsJRH3V1oQXWaY7sYzywMDQlpQhS8xrxzyfB7xGSRU5HovqxDPzyxOvq50',
  dq: 'hhiaQQrzHxjhRJ-j1WjPXmju1IS_ONIzq6wkxD_XQPtVrcqEIfI8tn1PgTyBo1bcBdiqBBY3aWgbSaM8Ml0uqTgUnAcbnAB6JC2ZpxJO2bpORIXKfGN5f86pJn9cPW8OXUKVZMt5UIsaIfDhYvOKHr5Br9SJ30g_zyGsFAnlfM8',
  qi: 'JienPfGUZogAYXC8WJ-U-UTbRFEEvrygHilNNwI8FqTywNYcKk1Xc0m0Cdt-Use72sxQG-5-PjtwF9sZ_3TUJS9rTgw0zfn3IFMtNz4txOewbjwkOz4MjRuHjXyX1Ti5vmL9uMaIlfb_0jHrrYDN2urIzEwvYv2fECbk2x59aJE',
};

export const idTokenPublicKey = {
  kty: 'RSA',
  n: 'rS_iO491_fxo4MEfoxcNVba0Z72XB_wuywPoXgYohSauOyXMZrzpT6qQExn4ev7cwF2qzb2k8rQjYz-2A0FjmCWCnQLfdiAxWBuzlLGJW2-6rPoRhZ16pID_Drd7X8Ra6qXnGcsI5Lwu3kj6UimuflgOiBHw2sJ2bu5HByXDN3gVNDK5mLZJLsnnKkfX13vLrhzScAP75zsaf6eOTuSO_Hbn1A-E8f4f07M3MHDoN_dnoNt4ucPPXJV0MGZv0ZrxPeDxUyiD1Qd4PHXdDiG3uIwW-s605PJ7NigxHm2L0e4vbSzHTVK1VJiF1wgUKD4XtRNguWEfPjN6CQacwgmBfw',
  e: 'AQAB',
};

export const generateIdToken = async (options?: {
  nonce?: string;
  claims?: Record<string, unknown>;
}): Promise<string> => {
  const key = await jose.importJWK(idTokenPrivateKey);

  const sign = new jose.SignJWT({
    sub_jwk: idTokenPublicKey,
    sub: 'sub',
    nonce: options?.nonce,
    ...(options?.claims ?? {}),
  }).setProtectedHeader({ alg: 'RS256' });

  if (!options?.claims?.iss) {
    sign.setIssuer('https://example.com');
  }

  if (!options?.claims?.aud) {
    sign.setAudience('clientId');
  }

  if (!options?.claims?.exp) {
    sign.setExpirationTime('1m');
  }

  if (!options?.claims?.iat) {
    sign.setIssuedAt();
  }

  return sign.sign(key);
};

interface ResponseExpectation {
  status: number;
  body?: string;
  headers?: Record<string, string>;
}

interface Expectation {
  url: string;
  method: 'GET' | 'POST';
  headers: Record<string, string>;
  body?: string;
  response: ResponseExpectation;
}

const getHttpStatusText = (code: number): string => {
  const statusTexts = {
    100: 'Continue',
    101: 'Switching Protocols',
    102: 'Processing',
    103: 'Early Hints',
    200: 'OK',
    201: 'Created',
    202: 'Accepted',
    203: 'Non-Authoritative Information',
    204: 'No Content',
    205: 'Reset Content',
    206: 'Partial Content',
    207: 'Multi-Status',
    208: 'Already Reported',
    226: 'IM Used',
    300: 'Multiple Choices',
    301: 'Moved Permanently',
    302: 'Found',
    303: 'See Other',
    304: 'Not Modified',
    305: 'Use Proxy',
    307: 'Temporary Redirect',
    308: 'Permanent Redirect',
    400: 'Bad Request',
    401: 'Unauthorized',
    402: 'Payment Required',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    406: 'Not Acceptable',
    407: 'Proxy Authentication Required',
    408: 'Request Timeout',
    409: 'Conflict',
    410: 'Gone',
    411: 'Length Required',
    412: 'Precondition Failed',
    413: 'Payload Too Large',
    414: 'URI Too Long',
    415: 'Unsupported Media Type',
    416: 'Range Not Satisfiable',
    417: 'Expectation Failed',
    418: "I'm a Teapot",
    421: 'Misdirected Request',
    422: 'Unprocessable Entity',
    423: 'Locked',
    424: 'Failed Dependency',
    425: 'Too Early',
    426: 'Upgrade Required',
    428: 'Precondition Required',
    429: 'Too Many Requests',
    431: 'Request Header Fields Too Large',
    451: 'Unavailable For Legal Reasons',
    500: 'Internal Server Error',
    501: 'Not Implemented',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
    505: 'HTTP Version Not Supported',
    506: 'Variant Also Negotiates',
    507: 'Insufficient Storage',
    508: 'Loop Detected',
    510: 'Not Extended',
    511: 'Network Authentication Required',
  };

  return statusTexts[code as keyof typeof statusTexts];
};

export const defaultMetadata = {
  issuer: 'https://example.com',
  jwks_uri: 'https://example.com/.well-known/openid-configuration/jwks',
  authorization_endpoint: 'https://example.com/connect/authorize',
  token_endpoint: 'https://example.com/connect/token',
  userinfo_endpoint: 'https://example.com/connect/userinfo',
  pushed_authorization_request_endpoint: 'https://example.com/connect/par',
  end_session_endpoint: 'https://example.com/connect/endsession',
  check_session_iframe: 'https://example.com/connect/checksession',
  revocation_endpoint: 'https://example.com/connect/revocation',
  introspection_endpoint: 'https://example.com/connect/introspect',
  device_authorization_endpoint:
    'https://example.com/connect/deviceauthorization',
  frontchannel_logout_supported: true,
  frontchannel_logout_session_supported: true,
  backchannel_logout_supported: true,
  backchannel_logout_session_supported: true,
  scopes_supported: ['openid', 'profile'],
  claims_supported: ['sub', 'name', 'profile'],
  grant_types_supported: ['authorization_code'],
  response_types_supported: ['code', 'token', 'id_token'],
  response_modes_supported: ['form_post', 'query', 'fragment'],
  token_endpoint_auth_methods_supported: ['client_secret_basic'],
  id_token_signing_alg_values_supported: ['RS256'],
  subject_types_supported: ['public'],
  code_challenge_methods_supported: ['plain', 'S256'],
  request_parameter_supported: true,
  request_uri_parameter_supported: false,
  request_object_signing_alg_values_supported: ['RS256'],
  require_pushed_authorization_requests: true,
};

export class AuthorizationServerFetchBuilder {
  private expectations: Expectation[] = [];

  constructor(private readonly authServerUrl = 'https://example.com') {}

  configureMetadata(options?: {
    responseCode?: number;
    metadata?: object;
  }): AuthorizationServerFetchBuilder {
    this.expectations.push({
      url: `${this.authServerUrl}/.well-known/openid-configuration`,
      headers: {},
      method: 'GET',
      response: {
        status: options?.responseCode ?? 200,
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(options?.metadata ?? defaultMetadata),
      },
    });

    return this;
  }

  configureJwks(options?: {
    responseCode?: number;
    jwks?: object;
  }): AuthorizationServerFetchBuilder {
    this.expectations.push({
      url: `${this.authServerUrl}/.well-known/openid-configuration/jwks`,
      headers: {},
      method: 'GET',
      response: {
        status: options?.responseCode ?? 200,
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(options?.jwks ?? { keys: [idTokenPublicKey] }),
      },
    });

    return this;
  }

  configurePar(options?: {
    responseCode?: number;
    body?: string;
    error?: string | null;
    error_description?: string | null;
  }): AuthorizationServerFetchBuilder {
    let body = undefined;
    let responseCode = options?.responseCode ?? 201;
    if (
      typeof options?.error !== 'undefined' ||
      typeof options?.error_description !== 'undefined'
    ) {
      responseCode = 400;
      body = {
        error: options.error ?? null,
        error_description: options.error_description ?? null,
      };
    } else {
      body = { request_uri: 'some uri', expires_in: 2000 };
    }

    this.expectations.push({
      url: `${this.authServerUrl}/connect/par`,
      headers: {
        authorization: 'Basic Y2xpZW50SWQ6',
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      method: 'POST',
      body: options?.body,
      response: {
        status: responseCode,
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
      },
    });

    return this;
  }

  configureTokenEndpoint(options?: {
    responseCode?: number;
    idToken?: string;
    accessToken?: string;
    refreshToken?: string;
    scope?: string;
    body?: string;
    error?: string | null;
    error_description?: string | null;
    skipIdToken?: boolean;
    skipScope?: boolean;
    skipExpiration?: boolean;
  }): AuthorizationServerFetchBuilder {
    let body = undefined;
    let responseCode = options?.responseCode ?? 200;
    if (
      typeof options?.error !== 'undefined' ||
      typeof options?.error_description !== 'undefined'
    ) {
      responseCode = 400;
      body = {
        error: options.error ?? null,
        error_description: options.error_description ?? null,
      };
    } else {
      body = {
        access_token: options?.accessToken ?? 'at',
        id_token: !options?.skipIdToken
          ? (options?.idToken ?? 'idtoken')
          : undefined,
        refresh_token: options?.refreshToken ?? 'rt',
        expires_in: !options?.skipExpiration ? 999 : undefined,
        scope: !options?.skipScope
          ? (options?.scope ?? 'openid offline_access')
          : undefined,
        token_type: 'Bearer',
      };
    }

    this.expectations.push({
      url: `${this.authServerUrl}/connect/token`,
      headers: {
        accept: 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
        authorization: 'Basic Y2xpZW50SWQ6',
      },
      body: options?.body,
      method: 'POST',
      response: {
        status: responseCode,
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
      },
    });

    return this;
  }

  configureRefreshToken(options?: {
    responseCode?: number;
    idToken?: string;
    accessToken?: string;
    refreshToken?: string;
    scope?: string;
    body?: string;
    error?: string | null;
    error_description?: string | null;
    skipIdToken?: boolean;
    skipExpiration?: boolean;
    skipScope?: boolean;
    skipRefreshToken?: boolean;
  }): AuthorizationServerFetchBuilder {
    this.expectations.push({
      url: `${this.authServerUrl}/connect/token`,
      headers: {
        accept: 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
        authorization: 'Basic Y2xpZW50SWQ6',
      },
      body: options?.body,
      method: 'POST',
      response: {
        status: options?.responseCode ?? 200,
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(
          options?.responseCode === 400
            ? {
                error: options.error,
                error_description: options.error_description,
              }
            : {
                access_token: options?.accessToken ?? 'at',
                id_token: !options?.skipIdToken
                  ? (options?.idToken ?? 'idtoken')
                  : undefined,
                refresh_token: !options?.skipRefreshToken
                  ? (options?.refreshToken ?? 'rt')
                  : undefined,
                expires_in: !options?.skipExpiration ? 999 : undefined,
                scope: !options?.skipScope
                  ? (options?.scope ?? 'openid offline_access')
                  : undefined,
                token_type: 'Bearer',
              }
        ),
      },
    });

    return this;
  }

  configureUserinfo(options?: {
    accessToken?: string;
    claims?: Record<string, unknown>;
    responseCode?: number;
    responseHeaders?: Record<string, string>;
  }): AuthorizationServerFetchBuilder {
    this.expectations.push({
      url: `${this.authServerUrl}/connect/userinfo`,
      headers: {
        authorization: `Bearer ${options?.accessToken ?? 'at'}`,
      },
      method: 'GET',
      response: {
        status: options?.responseCode ?? 200,
        headers: {
          'content-type': 'application/json',
          ...(options?.responseHeaders ?? {}),
        },
        body: JSON.stringify(
          options?.claims ?? {
            sub: 'sub',
            username: 'username',
          }
        ),
      },
    });

    return this;
  }

  configureRevokeToken(options?: {
    accessToken?: boolean;
    refreshToken?: boolean;
    responseCode?: number;
    tokenTypeHint?: boolean;
    error?: string | null;
    error_description?: string | null;
  }): AuthorizationServerFetchBuilder {
    if (options?.accessToken) {
      this.expectations.push({
        url: `${this.authServerUrl}/connect/revocation`,
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: 'Basic Y2xpZW50SWQ6',
        },
        body: `token=at${options.tokenTypeHint ? `&token_type_hint=access_token` : ''}`,
        method: 'POST',
        response: {
          status: options?.responseCode ?? 200,
          body: JSON.stringify(
            options?.responseCode === 400
              ? {
                  error: options?.error,
                  error_description: options.error_description,
                }
              : {}
          ),
        },
      });
    }

    if (options?.refreshToken) {
      this.expectations.push({
        url: `${this.authServerUrl}/connect/revocation`,
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: 'Basic Y2xpZW50SWQ6',
        },
        body: `token=rt${options.tokenTypeHint ? `&token_type_hint=refresh_token` : ''}`,
        method: 'POST',
        response: {
          status: options?.responseCode ?? 200,
        },
      });
    }

    return this;
  }

  public createSpy(): AuthorizationServerFetchBuilder {
    vi.spyOn(globalThis, 'fetch').mockImplementation(
      (input: string | URL | Request | RequestInit, init?: RequestInit) => {
        if (typeof input !== 'string' || (init && typeof init !== 'object')) {
          throw new Error(
            'Mock only implemented for (input: string, init: RequestInit) => Promise<Response>'
          );
        }

        const expectationIndex = this.expectations.findIndex(x => {
          const sameUrl = x.url === input;

          const sameMethod = x.method === (init?.method ?? 'GET').toUpperCase();

          const sameBody = x.body === init?.body?.toString();

          let headersPresent = true;

          const incomingHeaders = new Headers(init?.headers);

          for (const [key, value] of Object.entries(x.headers)) {
            if (incomingHeaders.get(key) !== value) {
              headersPresent = false;
              break;
            }
          }

          return sameUrl && sameBody && sameMethod && headersPresent;
        });

        if (expectationIndex === -1) {
          throw new Error(`Mock not setup for Request - ${input}`);
        }

        const [expectation] = this.expectations.splice(expectationIndex, 1);

        return Promise.resolve(
          new Response(expectation.response.body, {
            status: expectation.response.status,
            headers: expectation.response.headers,
            statusText: getHttpStatusText(expectation.response.status),
          })
        );
      }
    );

    return this;
  }

  public assert(): void {
    expect(
      this.expectations.length,
      this.expectations.map(x => x.url).join(',')
    ).toBe(0);
  }
}

export const fetchBuilder = (
  authServerUrl?: string
): AuthorizationServerFetchBuilder =>
  new AuthorizationServerFetchBuilder(authServerUrl);
