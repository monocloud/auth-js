/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import {
  MonoCloudOidcBackendClient,
  MonoCloudValidationError,
  MonoCloudHttpError,
  MonoCloudOPError,
} from '../src';
import {
  defaultMetadata,
  fetchBuilder,
  mtlsFetchSpy,
} from '@monocloud/auth-test-utils';
import { assertError, assertTokenError } from './utils';
import { now } from '../src/utils/internal';

const defaultClientOptions = {
  clientId: 'clientId',
};

const toBase64UrlBytes = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

const getCertificateHash = async (certificate: string): Promise<string> => {
  const pemMatch =
    /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(
      certificate
    );
  const encodedCertificate = (pemMatch?.[1] ?? certificate).replace(/\s+/g, '');
  const certificateBinary = atob(encodedCertificate);
  const certificateBytes = new Uint8Array(certificateBinary.length);

  for (let i = 0; i < certificateBinary.length; i++) {
    certificateBytes[i] = certificateBinary.charCodeAt(i);
  }

  const digest = await crypto.subtle.digest('SHA-256', certificateBytes);

  return toBase64UrlBytes(new Uint8Array(digest));
};

describe('MonoCloudOidcBackendClient.introspectAccessToken()', () => {
  describe('input validation', () => {
    it.each([null, ' '])(
      'should throw if access token is invalid',
      async accessToken => {
        const client = new MonoCloudOidcBackendClient(
          'example.com',
          'https://api.example.com',
          defaultClientOptions
        );

        await assertError(
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          client.introspectAccessToken(accessToken!),
          MonoCloudValidationError,
          'Access token must be a valid non-empty string'
        );
      }
    );

    it('should throw if introspection endpoint is missing from metadata', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata({
          metadata: {
            ...defaultMetadata,
            introspection_endpoint: undefined,
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertError(
        client.introspectAccessToken('some-token'),
        MonoCloudValidationError,
        'introspection_endpoint endpoint is required but not available in the issuer metadata'
      );

      fetchSpy.assert();
    });

    it('should throw if clientId is not configured', async () => {
      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com'
      );

      await assertError(
        client.introspectAccessToken('some-token'),
        MonoCloudValidationError,
        'The clientId option must be configured to introspect access tokens'
      );
    });
  });

  describe('HTTP errors', () => {
    it('should throw on introspection endpoint 400 error', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            error: 'invalid_request',
            error_description: 'Missing token parameter',
          },
          responseCode: 400,
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertError(
        client.introspectAccessToken('some-token'),
        MonoCloudOPError,
        'invalid_request',
        'Missing token parameter'
      );

      fetchSpy.assert();
    });

    it('should throw on introspection endpoint 400 error with fallback error values', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {},
          responseCode: 400,
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertError(
        client.introspectAccessToken('some-token'),
        MonoCloudOPError,
        'introspection_failed',
        'Token introspection failed'
      );

      fetchSpy.assert();
    });

    it('should throw on introspection endpoint unexpected status code', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {},
          responseCode: 500,
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertError(
        client.introspectAccessToken('some-token'),
        MonoCloudHttpError,
        'Error while performing token introspection. Unexpected status code: 500'
      );

      fetchSpy.assert();
    });

    it('should return a failed result if server is unreachable', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
        throw new Error('fetch failed');
      });

      const client = new MonoCloudOidcBackendClient(
        'server',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertError(
        client.introspectAccessToken('some-token'),
        MonoCloudHttpError,
        'fetch failed'
      );

      fetchSpy.mockClear();
    });
  });

  describe('active check', () => {
    it('should throw if the token is not active', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: { active: false },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token'),
        'Token is not active'
      );

      fetchSpy.assert();
    });

    it('should throw if active field is missing', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            iss: 'https://example.com',
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token'),
        'Token is not active'
      );

      fetchSpy.assert();
    });
  });

  describe('successful introspection', () => {
    it('should return claims with active field stripped', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 'user123',
            exp: now() + 60,
            scope: 'read write',
            client_id: 'clientId',
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      const result = await client.introspectAccessToken('some-token');

      expect(result.iss).toBe('https://example.com');
      expect(result.aud).toBe('https://api.example.com');
      expect(result.sub).toBe('user123');
      expect(result.scope).toBe('read write');
      expect(result).not.toHaveProperty('active');

      fetchSpy.assert();
    });
  });

  describe('claim validation', () => {
    it('should throw if the issuer does not match', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://wrong-issuer.com',
            sub: 'user123',
            exp: now() + 60,
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token'),
        'Invalid Issuer'
      );

      fetchSpy.assert();
    });

    it('should throw if subject is not a string', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 123,
            exp: now() + 60,
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token'),
        'Invalid subject'
      );

      fetchSpy.assert();
    });

    it('should throw if the audience does not match', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://wrong-audience.com',
            sub: 'user123',
            exp: now() + 60,
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token'),
        'Invalid audience claim'
      );

      fetchSpy.assert();
    });

    it('should pass when exp is not present in the introspection response', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 'user123',
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      const result = await client.introspectAccessToken('some-token');

      expect(result.sub).toBe('user123');
      expect(result.exp).toBeUndefined();

      fetchSpy.assert();
    });

    it('should throw if the token is expired', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 'user123',
            exp: 2,
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token'),
        'Unexpected "exp" (expiration time) claim value, timestamp is <= now()'
      );

      fetchSpy.assert();
    });

    it('should pass when nbf is present and valid', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            exp: now() + 60,
            nbf: now() - 10,
            sub: 'user123',
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      const result = await client.introspectAccessToken('some-token');

      expect(result.nbf).toBe(now() - 10);

      fetchSpy.assert();
    });

    it('should throw if nbf is in the future', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 'user123',
            exp: now() + 60,
            nbf: 999999999999999,
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token'),
        'Unexpected "nbf" (not before) claim value, timestamp is > now()'
      );

      fetchSpy.assert();
    });
  });

  describe('scope validation', () => {
    it('should throw if required scopes are not present', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 'user123',
            exp: now() + 60,
            scope: 'read',
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token', {
          scopes: ['read', 'write'],
        }),
        'Token is missing required scopes'
      );

      fetchSpy.assert();
    });

    it('should pass if all required scopes are present', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 'user123',
            exp: now() + 60,
            scope: 'read write admin',
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      const result = await client.introspectAccessToken('some-token', {
        scopes: ['read', 'write'],
      });

      expect(result.scope).toBe('read write admin');

      fetchSpy.assert();
    });
  });

  describe('clock skew and tolerance setters', () => {
    it('should apply clock skew set via setClockSkew', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 'user123',
            exp: now() + 10,
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );
      client.setClockSkew(1000);
      client.setClockTolerance(1);

      await assertTokenError(
        client.introspectAccessToken('some-token'),
        'Unexpected "exp" (expiration time) claim value, timestamp is <= now()'
      );

      fetchSpy.assert();
    });
  });

  describe('exp and nbf type validation', () => {
    it('should throw if exp claim type is not a number', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 'user123',
            exp: 'not-a-number',
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token'),
        'Unexpected "exp" (expiration time) claim type'
      );

      fetchSpy.assert();
    });

    it('should throw if nbf claim type is not a number', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 'user123',
            exp: now() + 60,
            nbf: 'not-a-number',
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token'),
        'Unexpected "nbf" (not before) claim type'
      );

      fetchSpy.assert();
    });
  });

  describe('group validation', () => {
    it('should throw if required groups are not present', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 'user123',
            exp: now() + 60,
            groups: ['readers'],
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token', {
          groups: ['admins'],
        }),
        'Token is missing required groups'
      );

      fetchSpy.assert();
    });

    it('should pass if required groups are present', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 'user123',
            exp: now() + 60,
            groups: ['admins', 'readers'],
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      const result = await client.introspectAccessToken('some-token', {
        groups: ['admins'],
      });

      expect(result.sub).toBe('user123');

      fetchSpy.assert();
    });

    it('should use custom groupsClaim from constructor options', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 'user123',
            exp: now() + 60,
            roles: ['admin'],
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        {
          ...defaultClientOptions,
          groupOptions: {
            groupsClaim: 'roles',
          },
        }
      );

      const result = await client.introspectAccessToken('some-token', {
        groups: ['admin'],
      });

      expect(result.sub).toBe('user123');

      fetchSpy.assert();
    });

    it('should require all groups when matchAll is set via constructor', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            active: true,
            iss: 'https://example.com',
            aud: 'https://api.example.com',
            sub: 'user123',
            exp: now() + 60,
            groups: ['admins'],
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        {
          ...defaultClientOptions,
          groupOptions: {
            matchAll: true,
          },
        }
      );

      await assertTokenError(
        client.introspectAccessToken('some-token', {
          groups: ['admins', 'writers'],
        }),
        'Token is missing required groups'
      );

      fetchSpy.assert();
    });
  });

  describe('certificate binding validation', () => {
    const baseClaims = {
      active: true,
      iss: 'https://example.com',
      aud: 'https://api.example.com',
      sub: 'user123',
      exp: now() + 60,
    };

    it('should throw if client certificate is missing', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            ...baseClaims,
            cnf: { 'x5t#S256': 'unused' },
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token', {
          validateCertificateBinding: true,
        }),
        'Client certificate is not present'
      );

      fetchSpy.assert();
    });

    it('should throw if client certificate is malformed', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            ...baseClaims,
            cnf: { 'x5t#S256': 'unused' },
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token', {
          validateCertificateBinding: true,
          clientCertificate: '@@@invalid-base64@@@',
        }),
        'Client certificate is malformed'
      );

      fetchSpy.assert();
    });

    it("should throw if the access token does not include a 'cnf' claim", async () => {
      const certificate = `-----BEGIN CERTIFICATE-----
AQIDBAUGBwg=
-----END CERTIFICATE-----`;

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            ...baseClaims,
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token', {
          validateCertificateBinding: true,
          clientCertificate: certificate,
        }),
        "Access token does not contain a 'cnf' (confirmation) claim for certificate binding"
      );

      fetchSpy.assert();
    });

    it("should throw if the 'cnf' claim is malformed JSON", async () => {
      const certificate = `-----BEGIN CERTIFICATE-----
AQIDBAUGBwg=
-----END CERTIFICATE-----`;

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            ...baseClaims,
            cnf: '{"x5t#S256"',
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token', {
          validateCertificateBinding: true,
          clientCertificate: certificate,
        }),
        "Malformed 'cnf' claim for certificate binding"
      );

      fetchSpy.assert();
    });

    it("should throw if the 'cnf' claim cannot be parsed into an object", async () => {
      const certificate = `-----BEGIN CERTIFICATE-----
AQIDBAUGBwg=
-----END CERTIFICATE-----`;

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            ...baseClaims,
            cnf: [],
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token', {
          validateCertificateBinding: true,
          clientCertificate: certificate,
        }),
        "The 'cnf' claim could not be parsed"
      );

      fetchSpy.assert();
    });

    it("should throw if the 'cnf' claim does not contain x5t#S256", async () => {
      const certificate = `-----BEGIN CERTIFICATE-----
AQIDBAUGBwg=
-----END CERTIFICATE-----`;

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            ...baseClaims,
            cnf: {},
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token', {
          validateCertificateBinding: true,
          clientCertificate: certificate,
        }),
        "The 'cnf' claim does not contain an 'x5t#S256' member specifying the certificate hash for binding"
      );

      fetchSpy.assert();
    });

    it('should throw if certificate hash does not match token cnf hash', async () => {
      const certificate = `-----BEGIN CERTIFICATE-----
AQIDBAUGBwg=
-----END CERTIFICATE-----`;

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            ...baseClaims,
            cnf: {
              'x5t#S256': 'different-hash',
            },
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.introspectAccessToken('some-token', {
          validateCertificateBinding: true,
          clientCertificate: certificate,
        }),
        'The certificate hash in the access token does not match the presented client certificate (certificate binding validation failed)'
      );

      fetchSpy.assert();
    });

    it('should validate certificate binding with PEM certificate and object cnf claim', async () => {
      const certificate = `-----BEGIN CERTIFICATE-----
AQIDBAUGBwg=
-----END CERTIFICATE-----`;
      const certificateHash = await getCertificateHash(certificate);

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            ...baseClaims,
            cnf: { 'x5t#S256': certificateHash },
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      const result = await client.introspectAccessToken('some-token', {
        validateCertificateBinding: true,
        clientCertificate: certificate,
      });

      expect(result.sub).toBe('user123');

      fetchSpy.assert();
    });

    it('should validate certificate binding with base64 certificate and string cnf claim', async () => {
      const certificate = 'AQIDBAUGBwg=';
      const certificateHash = await getCertificateHash(certificate);

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureIntrospection({
          responseBody: {
            ...baseClaims,
            cnf: JSON.stringify({ 'x5t#S256': certificateHash }),
          },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      const result = await client.introspectAccessToken('some-token', {
        validateCertificateBinding: true,
        clientCertificate: certificate,
      });

      expect(result.sub).toBe('user123');

      fetchSpy.assert();
    });
  });

  describe('mTLS endpoint aliases', () => {
    const activeResponse = {
      active: true,
      iss: 'https://example.com',
      aud: 'https://api.example.com',
      sub: 'sub',
      exp: 9999999999,
    };

    it('should introspect against the default mTLS endpoint alias for mTLS auth methods', async () => {
      const fetchSpy = mtlsFetchSpy({ response: activeResponse });

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        { clientId: 'clientId', clientAuthMethod: 'tls_client_auth' }
      );

      const result = await client.introspectAccessToken('some-token');

      expect(result.sub).toBe('sub');
      expect(fetchSpy).toHaveBeenCalledWith(
        'https://mtls.example.com/connect/introspect',
        expect.objectContaining({ method: 'POST' })
      );

      fetchSpy.mockClear();
    });

    it('should introspect against the trust store mTLS endpoint alias when a trustStoreId is configured', async () => {
      const fetchSpy = mtlsFetchSpy({ response: activeResponse });

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        {
          clientId: 'clientId',
          clientAuthMethod: 'tls_client_auth',
          trustStoreId: 'trust-store-1',
        }
      );

      const result = await client.introspectAccessToken('some-token');

      expect(result.sub).toBe('sub');
      expect(fetchSpy).toHaveBeenCalledWith(
        'https://mtls.example.com/trust-store-1/connect/introspect',
        expect.objectContaining({ method: 'POST' })
      );

      fetchSpy.mockClear();
    });

    it('should throw if no mTLS endpoint alias is available for an mTLS auth method', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata({
          metadata: { ...defaultMetadata, mtls_endpoint_aliases: undefined },
        })
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        { clientId: 'clientId', clientAuthMethod: 'tls_client_auth' }
      );

      await assertError(
        client.introspectAccessToken('some-token'),
        MonoCloudValidationError,
        'mTLS introspection_endpoint is required but not available in the issuer metadata'
      );

      fetchSpy.assert();
    });

    it('should throw if the configured trust store has no mTLS endpoint alias', async () => {
      const fetchSpy = fetchBuilder().configureMetadata().createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        {
          clientId: 'clientId',
          clientAuthMethod: 'tls_client_auth',
          trustStoreId: 'nonexistent',
        }
      );

      await assertError(
        client.introspectAccessToken('some-token'),
        MonoCloudValidationError,
        "mTLS introspection_endpoint is required but not available for trust store 'nonexistent' in the issuer metadata"
      );

      fetchSpy.assert();
    });
  });
});
