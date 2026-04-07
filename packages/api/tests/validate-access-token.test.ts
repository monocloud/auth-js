/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import {
  MonoCloudApiClient,
  MonoCloudApiHttpError,
  MonoCloudApiOPError,
  MonoCloudApiTokenError,
} from '../src';
import { MonoCloudApiValidationError } from '../src/errors/monocloud-api-validation-error';
import {
  defaultMetadata,
  fetchBuilder,
  generateIdToken,
} from '@monocloud/auth-test-utils';
import { assertError, defaultOptions } from './utils';
import { now } from '../src/utils/internal';

const assertTokenError = async (
  promise: Promise<unknown>,
  error: string
): Promise<void> => await assertError(promise, MonoCloudApiTokenError, error);

describe('MonoCloudApiClient.validateAccessToken()', () => {
  describe('input validation', () => {
    it.each([null, ' '])(
      'should throw if access token is invalid',
      async accessToken => {
        const client = new MonoCloudApiClient(
          'example.com',
          'clientId',
          defaultOptions
        );

        await assertError(
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          client.validateAccessToken(accessToken!),
          MonoCloudApiValidationError,
          'Access token is required for validation'
        );
      }
    );
  });

  describe('JWT validation', () => {
    it('should validate a JWT access token and return claims', async () => {
      const exp = now() + 60;
      const iat = now();

      const jwt = await generateIdToken({
        claims: {
          aud: 'https://api.example.com',
          iss: 'https://example.com',
          exp,
          iat,
          custom: 'value',
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      const result = await client.validateAccessToken(jwt);

      fetchSpy.assert();

      expect(result.iss).toBe('https://example.com');
      expect(result.aud).toBe('https://api.example.com');
      expect(result.exp).toBe(exp);
      expect(result.iat).toBe(iat);
      expect(result.custom).toBe('value');
    });

    it('should not validate a JWT without a valid header', async () => {
      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertTokenError(
        client.validateAccessToken('.payload.signature'),
        'Failed to parse JWT Header'
      );
    });

    it('should not validate a JWT with an invalid header object', async () => {
      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      const promise = client.validateAccessToken(
        'W3siYWxnIjogIlJTMjU2IiwgInR5cCI6ICJzdHJpbmciLCAiY3JpdCI6IFtdfV0.payload.signature'
      );

      await assertTokenError(promise, 'JWT Header must be a top level object');
    });

    it('should not validate a JWT with a crit header parameter', async () => {
      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      const promise = client.validateAccessToken(
        'eyJhbGciOiAiUlMyNTYiLCAidHlwIjogInN0cmluZyIsICJjcml0IjogW119.payload.signature'
      );

      await assertTokenError(promise, 'Unexpected JWT "crit" header parameter');
    });

    it('should fail if the JWT signature is invalid', async () => {
      let jwt = await generateIdToken({
        claims: {
          aud: 'https://api.example.com',
          iss: 'https://example.com',
        },
      });

      const [header, payload] = jwt.split('.');
      jwt = `${header}.${payload}.invalidsignature`;

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertTokenError(
        client.validateAccessToken(jwt),
        'JWT signature verification failed'
      );

      fetchSpy.assert();
    });

    it('should fail if the JWT payload is invalid', async () => {
      const cryptoSpy = vi
        .spyOn(crypto.subtle, 'verify')
        .mockReturnValue(Promise.resolve(true));

      let jwt = await generateIdToken();
      const [header, , signature] = jwt.split('.');
      jwt = `${header}.ew.${signature}`;

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertTokenError(
        client.validateAccessToken(jwt),
        'Failed to parse JWT Payload'
      );

      fetchSpy.assert();
      cryptoSpy.mockClear();
    });

    it('should fail if the JWT payload is not an object', async () => {
      const cryptoSpy = vi
        .spyOn(crypto.subtle, 'verify')
        .mockReturnValue(Promise.resolve(true));

      let jwt = await generateIdToken();
      const [header, , signature] = jwt.split('.');
      jwt = `${header}.W10.${signature}`;

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertTokenError(
        client.validateAccessToken(jwt),
        'JWT Payload must be a top level object'
      );

      fetchSpy.assert();
      cryptoSpy.mockClear();
    });
  });

  describe('opaque token validation', () => {
    it('should validate an opaque token via introspection', async () => {
      const introspectionResponse = {
        active: true,
        iss: 'https://example.com',
        aud: 'https://api.example.com',
        sub: 'user123',
        exp: now() + 60,
        scope: 'read write',
        client_id: 'clientId',
      };

      const fetchSpy = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation((input: string | URL | Request) => {
          const url = typeof input === 'string' ? input : input.toString();

          if (url.includes('.well-known/openid-configuration')) {
            return Promise.resolve(
              new Response(JSON.stringify(defaultMetadata), {
                status: 200,
                headers: { 'content-type': 'application/json' },
              })
            );
          }

          if (url.includes('introspect')) {
            return Promise.resolve(
              new Response(JSON.stringify(introspectionResponse), {
                status: 200,
                headers: { 'content-type': 'application/json' },
              })
            );
          }

          throw new Error(`Unexpected request: ${url}`);
        });

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      const result = await client.validateAccessToken('opaque-token');

      expect(result.iss).toBe('https://example.com');
      expect(result.aud).toBe('https://api.example.com');
      expect(result.sub).toBe('user123');
      expect(result.scope).toBe('read write');
      expect(result).not.toHaveProperty('active');

      fetchSpy.mockClear();
    });

    it('should throw if the opaque token is not active', async () => {
      const fetchSpy = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation((input: string | URL | Request) => {
          const url = typeof input === 'string' ? input : input.toString();

          if (url.includes('.well-known/openid-configuration')) {
            return Promise.resolve(
              new Response(JSON.stringify(defaultMetadata), {
                status: 200,
                headers: { 'content-type': 'application/json' },
              })
            );
          }

          if (url.includes('introspect')) {
            return Promise.resolve(
              new Response(JSON.stringify({ active: false }), {
                status: 200,
                headers: { 'content-type': 'application/json' },
              })
            );
          }

          throw new Error(`Unexpected request: ${url}`);
        });

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertTokenError(
        client.validateAccessToken('opaque-token'),
        'Token is not active'
      );

      fetchSpy.mockClear();
    });

    it('should use client_secret_post by default for introspection', async () => {
      const introspectionResponse = {
        active: true,
        iss: 'https://example.com',
        aud: 'https://api.example.com',
        exp: now() + 60,
      };

      let capturedBody: string | undefined;

      const fetchSpy = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation(
          (input: string | URL | Request, init?: RequestInit) => {
            const url = typeof input === 'string' ? input : input.toString();

            if (url.includes('.well-known/openid-configuration')) {
              return Promise.resolve(
                new Response(JSON.stringify(defaultMetadata), {
                  status: 200,
                  headers: { 'content-type': 'application/json' },
                })
              );
            }

            if (url.includes('introspect')) {
              capturedBody = init?.body?.toString();
              return Promise.resolve(
                new Response(JSON.stringify(introspectionResponse), {
                  status: 200,
                  headers: { 'content-type': 'application/json' },
                })
              );
            }

            throw new Error(`Unexpected request: ${url}`);
          }
        );

      const client = new MonoCloudApiClient('example.com', 'clientId', {
        clientSecret: 'my-secret',
        audience: 'https://api.example.com',
      });

      await client.validateAccessToken('opaque-token');

      expect(capturedBody).toContain('client_id=clientId');
      expect(capturedBody).toContain('client_secret=my-secret');

      fetchSpy.mockClear();
    });

    it('should use client_secret_basic when configured', async () => {
      const introspectionResponse = {
        active: true,
        iss: 'https://example.com',
        aud: 'https://api.example.com',
        exp: now() + 60,
      };

      let capturedHeaders: Record<string, string> | undefined;

      const fetchSpy = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation(
          (input: string | URL | Request, init?: RequestInit) => {
            const url = typeof input === 'string' ? input : input.toString();

            if (url.includes('.well-known/openid-configuration')) {
              return Promise.resolve(
                new Response(JSON.stringify(defaultMetadata), {
                  status: 200,
                  headers: { 'content-type': 'application/json' },
                })
              );
            }

            if (url.includes('introspect')) {
              capturedHeaders = init?.headers as Record<string, string>;
              return Promise.resolve(
                new Response(JSON.stringify(introspectionResponse), {
                  status: 200,
                  headers: { 'content-type': 'application/json' },
                })
              );
            }

            throw new Error(`Unexpected request: ${url}`);
          }
        );

      const client = new MonoCloudApiClient('example.com', 'clientId', {
        clientSecret: 'my-secret',
        audience: 'https://api.example.com',
        clientAuthMethod: 'client_secret_basic',
      });

      await client.validateAccessToken('opaque-token');

      expect(capturedHeaders?.authorization).toBe(
        `Basic ${btoa('clientId:my-secret')}`
      );

      fetchSpy.mockClear();
    });

    it('should throw on introspection endpoint 400 error', async () => {
      const fetchSpy = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation((input: string | URL | Request) => {
          const url = typeof input === 'string' ? input : input.toString();

          if (url.includes('.well-known/openid-configuration')) {
            return Promise.resolve(
              new Response(JSON.stringify(defaultMetadata), {
                status: 200,
                headers: { 'content-type': 'application/json' },
              })
            );
          }

          if (url.includes('introspect')) {
            return Promise.resolve(
              new Response(
                JSON.stringify({
                  error: 'invalid_request',
                  error_description: 'Missing token parameter',
                }),
                {
                  status: 400,
                  headers: { 'content-type': 'application/json' },
                }
              )
            );
          }

          throw new Error(`Unexpected request: ${url}`);
        });

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertError(
        client.validateAccessToken('opaque-token'),
        MonoCloudApiOPError,
        'invalid_request',
        'Missing token parameter'
      );

      fetchSpy.mockClear();
    });

    it('should throw on introspection endpoint 401 error', async () => {
      const fetchSpy = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation((input: string | URL | Request) => {
          const url = typeof input === 'string' ? input : input.toString();

          if (url.includes('.well-known/openid-configuration')) {
            return Promise.resolve(
              new Response(JSON.stringify(defaultMetadata), {
                status: 200,
                headers: { 'content-type': 'application/json' },
              })
            );
          }

          if (url.includes('introspect')) {
            return Promise.resolve(
              new Response('', {
                status: 401,
              })
            );
          }

          throw new Error(`Unexpected request: ${url}`);
        });

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertError(
        client.validateAccessToken('opaque-token'),
        MonoCloudApiHttpError,
        'Client authentication failed at the introspection endpoint'
      );

      fetchSpy.mockClear();
    });

    it('should throw on introspection endpoint unexpected status code', async () => {
      const fetchSpy = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation((input: string | URL | Request) => {
          const url = typeof input === 'string' ? input : input.toString();

          if (url.includes('.well-known/openid-configuration')) {
            return Promise.resolve(
              new Response(JSON.stringify(defaultMetadata), {
                status: 200,
                headers: { 'content-type': 'application/json' },
              })
            );
          }

          if (url.includes('introspect')) {
            return Promise.resolve(
              new Response('', {
                status: 500,
              })
            );
          }

          throw new Error(`Unexpected request: ${url}`);
        });

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertError(
        client.validateAccessToken('opaque-token'),
        MonoCloudApiHttpError,
        'Error while performing token introspection. Unexpected status code: 500'
      );

      fetchSpy.mockClear();
    });

    it('should throw if introspection endpoint is missing from metadata', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata({
          metadata: { ...defaultMetadata, introspection_endpoint: undefined },
        })
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertError(
        client.validateAccessToken('opaque-token'),
        MonoCloudApiValidationError,
        'introspection_endpoint endpoint is required but not available in the issuer metadata'
      );

      fetchSpy.assert();
    });
  });

  describe('claim validation', () => {
    it('should throw if the issuer does not match', async () => {
      const jwt = await generateIdToken({
        claims: {
          aud: 'https://api.example.com',
          iss: 'https://wrong-issuer.com',
        },
      });

      const cryptoSpy = vi
        .spyOn(crypto.subtle, 'verify')
        .mockReturnValue(Promise.resolve(true));

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertTokenError(client.validateAccessToken(jwt), 'Invalid Issuer');

      fetchSpy.assert();
      cryptoSpy.mockClear();
    });

    it('should throw if the audience does not match', async () => {
      const jwt = await generateIdToken({
        claims: {
          aud: 'https://wrong-audience.com',
          iss: 'https://example.com',
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertTokenError(
        client.validateAccessToken(jwt),
        'Invalid audience claim'
      );
      fetchSpy.assert();
    });

    it('should throw if the audience array does not include the expected audience', async () => {
      const jwt = await generateIdToken({
        claims: {
          aud: ['https://other-api.example.com'],
          iss: 'https://example.com',
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertTokenError(
        client.validateAccessToken(jwt),
        'Invalid audience claim'
      );
      fetchSpy.assert();
    });

    it('should accept an audience array that includes the expected audience', async () => {
      const exp = now() + 60;

      const jwt = await generateIdToken({
        claims: {
          aud: ['https://api.example.com', 'https://other.example.com'],
          iss: 'https://example.com',
          exp,
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      const result = await client.validateAccessToken(jwt);

      expect(result.aud).toEqual([
        'https://api.example.com',
        'https://other.example.com',
      ]);
      fetchSpy.assert();
    });

    it('should throw if exp claim type is not a number', async () => {
      const jwt = await generateIdToken({
        claims: {
          aud: 'https://api.example.com',
          iss: 'https://example.com',
          exp: {},
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertTokenError(
        client.validateAccessToken(jwt),
        'Unexpected "exp" (expiration time) claim type'
      );
      fetchSpy.assert();
    });

    it('should throw if the token is expired', async () => {
      const jwt = await generateIdToken({
        claims: {
          aud: 'https://api.example.com',
          iss: 'https://example.com',
          exp: 2,
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertTokenError(
        client.validateAccessToken(jwt),
        'Unexpected "exp" (expiration time) claim value, timestamp is <= now()'
      );
      fetchSpy.assert();
    });

    it('should throw if nbf claim type is not a number', async () => {
      const jwt = await generateIdToken({
        claims: {
          aud: 'https://api.example.com',
          iss: 'https://example.com',
          exp: now() + 60,
          nbf: {},
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertTokenError(
        client.validateAccessToken(jwt),
        'Unexpected "nbf" (not before) claim type'
      );
      fetchSpy.assert();
    });

    it('should throw if the token is not yet valid (nbf in the future)', async () => {
      const jwt = await generateIdToken({
        claims: {
          aud: 'https://api.example.com',
          iss: 'https://example.com',
          exp: now() + 60,
          nbf: 999999999999999,
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      await assertTokenError(
        client.validateAccessToken(jwt),
        'Unexpected "nbf" (not before) claim value, timestamp is > now()'
      );
      fetchSpy.assert();
    });

    it('should pass claim validation when all claims are valid', async () => {
      const exp = now() + 60;
      const iat = now();
      const nbf = now() - 10;

      const jwt = await generateIdToken({
        claims: {
          aud: 'https://api.example.com',
          iss: 'https://example.com',
          exp,
          iat,
          nbf,
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      const result = await client.validateAccessToken(jwt);

      expect(result.exp).toBe(exp);
      expect(result.iat).toBe(iat);
      expect(result.nbf).toBe(nbf);
      fetchSpy.assert();
    });

    it('should pass validation when iss, aud, exp, nbf claims are absent', async () => {
      const cryptoSpy = vi
        .spyOn(crypto.subtle, 'verify')
        .mockReturnValue(Promise.resolve(true));

      const jwt = await generateIdToken({
        claims: {
          iss: undefined,
          aud: 'https://api.example.com',
          exp: undefined,
          nbf: undefined,
          iat: undefined,
          sub: 'user123',
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudApiClient(
        'example.com',
        'clientId',
        defaultOptions
      );

      const result = await client.validateAccessToken(jwt);

      expect(result.sub).toBe('user123');

      fetchSpy.assert();
      cryptoSpy.mockClear();
    });
  });
});
