/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import { now } from '../src/utils/internal';
import {
  generateIdToken,
  idTokenPublicKey,
  fetchBuilder,
} from '@monocloud/auth-test-utils';
import { MonoCloudOidcBackendClient, MonoCloudValidationError } from '../src';
import { assertError, assertTokenError } from './utils';

const defaultClientOptions = {
  clientId: 'clientId',
};

const toBase64Url = (value: string): string =>
  btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

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

const buildJwt = (
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signature = 'c2ln'
): string => {
  const encodedHeader = toBase64Url(JSON.stringify(header));
  const encodedPayload = toBase64Url(JSON.stringify(payload));

  return `${encodedHeader}.${encodedPayload}.${signature}`;
};

describe('MonoCloudOidcBackendClient.validateJwtAccessToken()', () => {
  describe('input validation', () => {
    it.each([null, ' ', ''])(
      'should not validate invalid access token',
      async accessToken => {
        const client = new MonoCloudOidcBackendClient(
          'example.com',
          'https://api.example.com',
          defaultClientOptions
        );

        await assertError(
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          client.validateJwtAccessToken(accessToken!),
          MonoCloudValidationError,
          'Access token must be a valid non-empty string'
        );
      }
    );

    it('should not validate a two-part dotted token', async () => {
      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.validateJwtAccessToken('header.payload'),
        'JWT access token must have a header, payload and signature'
      );
    });
  });

  describe('header validation', () => {
    it('should not validate a JWT without a valid header', async () => {
      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.validateJwtAccessToken('.payload.signature'),
        'Failed to parse JWT Header'
      );
    });

    it('should not validate a JWT with an invalid header object', async () => {
      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.validateJwtAccessToken(
          'W3siYWxnIjogIlJTMjU2IiwgInR5cCI6ICJzdHJpbmciLCAiY3JpdCI6IFtdfV0.payload.signature'
        ),
        'JWT Header must be a top level object'
      );
    });

    it('should not validate a JWT with a crit header parameter', async () => {
      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.validateJwtAccessToken(
          'eyJhbGciOiAiUlMyNTYiLCAidHlwIjogInN0cmluZyIsICJjcml0IjogW119.payload.signature'
        ),
        'Unexpected JWT "crit" header parameter'
      );
    });

    it('should not validate a JWT with an unsupported typ header', async () => {
      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      const jwt = buildJwt(
        {
          alg: 'RS256',
          typ: 'JWT',
        },
        {
          iss: 'https://example.com',
          aud: 'https://api.example.com',
          sub: 'user123',
          exp: now() + 60,
        }
      );

      await assertTokenError(
        client.validateJwtAccessToken(jwt),
        'Invalid token type'
      );
    });

    it('should allow typ header value at+jwt', async () => {
      const cryptoSpy = vi
        .spyOn(crypto.subtle, 'verify')
        .mockReturnValue(Promise.resolve(true));

      const jwt = buildJwt(
        {
          alg: 'RS256',
          typ: 'at+jwt',
        },
        {
          iss: 'https://example.com',
          aud: 'https://api.example.com',
          sub: 'sub',
          exp: now() + 60,
        }
      );

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      const result = await client.validateJwtAccessToken(jwt, {
        jwks: { keys: [idTokenPublicKey] },
      });

      expect(result.sub).toBe('sub');
      expect(result.iss).toBe('https://example.com');

      cryptoSpy.mockRestore();
    });
  });

  describe('signature validation', () => {
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

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.validateJwtAccessToken(jwt),
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

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.validateJwtAccessToken(jwt),
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

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.validateJwtAccessToken(jwt),
        'JWT Payload must be a top level object'
      );

      fetchSpy.assert();
      cryptoSpy.mockClear();
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

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.validateJwtAccessToken(jwt),
        'Invalid Issuer'
      );

      fetchSpy.assert();
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

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.validateJwtAccessToken(jwt),
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

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      const result = await client.validateJwtAccessToken(jwt);

      expect(result.aud).toEqual([
        'https://api.example.com',
        'https://other.example.com',
      ]);

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

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.validateJwtAccessToken(jwt),
        'Unexpected "exp" (expiration time) claim value, timestamp is <= now()'
      );

      fetchSpy.assert();
    });

    it('should apply clock skew and tolerance provided in constructor options', async () => {
      const jwt = await generateIdToken({
        claims: {
          aud: 'https://api.example.com',
          iss: 'https://example.com',
          exp: now() + 10,
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        {
          ...defaultClientOptions,
          clockSkew: 1000,
          clockTolerance: 1,
        }
      );

      await assertTokenError(
        client.validateJwtAccessToken(jwt),
        'Unexpected "exp" (expiration time) claim value, timestamp is <= now()'
      );

      fetchSpy.assert();
    });

    it('should throw if required scopes are not present', async () => {
      const jwt = await generateIdToken({
        claims: {
          aud: 'https://api.example.com',
          iss: 'https://example.com',
          exp: now() + 60,
          scope: 'read',
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.validateJwtAccessToken(jwt, {
          scopes: ['read', 'write'],
        }),
        'Token is missing required scopes'
      );

      fetchSpy.assert();
    });

    it('should throw if required groups are not present', async () => {
      const jwt = await generateIdToken({
        claims: {
          aud: 'https://api.example.com',
          iss: 'https://example.com',
          exp: now() + 60,
          groups: ['readers'],
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      await assertTokenError(
        client.validateJwtAccessToken(jwt, {
          groups: ['admins'],
        }),
        'Token is missing required groups'
      );

      fetchSpy.assert();
    });
  });

  describe('certificate binding validation', () => {
    it('should validate certificate binding for JWT access tokens', async () => {
      const certificate = `-----BEGIN CERTIFICATE-----
AQIDBAUGBwg=
-----END CERTIFICATE-----`;
      const certificateHash = await getCertificateHash(certificate);
      const exp = now() + 60;

      const jwt = await generateIdToken({
        claims: {
          aud: 'https://api.example.com',
          iss: 'https://example.com',
          exp,
          cnf: {
            'x5t#S256': certificateHash,
          },
        },
      });

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureJwks()
        .createSpy();

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      const result = await client.validateJwtAccessToken(jwt, {
        validateCertificateBinding: true,
        clientCertificate: certificate,
      });

      expect(result.cnf).toEqual({ 'x5t#S256': certificateHash });

      fetchSpy.assert();
    });
  });

  describe('successful validation', () => {
    it('should validate and return claims from a valid JWT access token', async () => {
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

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      const result = await client.validateJwtAccessToken(jwt);

      expect(result.iss).toBe('https://example.com');
      expect(result.aud).toBe('https://api.example.com');
      expect(result.exp).toBe(exp);
      expect(result.iat).toBe(iat);
      expect(result.custom).toBe('value');

      fetchSpy.assert();
    });

    it('should use pre-fetched JWKS when provided', async () => {
      const exp = now() + 60;

      const jwt = await generateIdToken({
        claims: {
          aud: 'https://api.example.com',
          iss: 'https://example.com',
          exp,
        },
      });

      const client = new MonoCloudOidcBackendClient(
        'example.com',
        'https://api.example.com',
        defaultClientOptions
      );

      const result = await client.validateJwtAccessToken(jwt, {
        jwks: { keys: [idTokenPublicKey] },
      });

      expect(result.iss).toBe('https://example.com');
    });
  });
});
