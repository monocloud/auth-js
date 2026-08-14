/* eslint-disable import/no-extraneous-dependencies */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AccessTokenClaims,
  MonoCloudOidcBackendClient,
  MonoCloudTokenError,
  MonoCloudValidationError,
} from '@monocloud/auth-core';
import { freeze, reset } from 'timekeeper';
import { now } from '@monocloud/auth-core/internal';
import { MonoCloudBackendNodeClient } from '../src/monocloud-backend-node-client';
import { IIntrospectionCache } from '../src/types';

const baseOptions = {
  tenantDomain: 'https://example.monocloud.com',
  audience: 'https://api.example.com',
  clientId: 'client_id',
  clientSecret: 'client_secret',
};

const buildClaims = (
  overrides: Partial<AccessTokenClaims> = {}
): AccessTokenClaims => ({
  iss: baseOptions.tenantDomain,
  aud: baseOptions.audience,
  sub: 'sub',
  exp: 9999999999,
  iat: 0,
  ...overrides,
});

const jwtToken = 'header.payload.signature';
const opaqueToken = 'opaque-access-token';

describe('MonoCloudBackendNodeClient', () => {
  beforeEach(() => {
    freeze(1_700_000_000 * 1000);
  });

  afterEach(() => {
    reset();
  });

  describe('constructor', () => {
    it('should throw when required options are missing', () => {
      expect(() => new MonoCloudBackendNodeClient()).toThrow(
        MonoCloudValidationError
      );
    });

    it('should successfully create an instance with valid options', () => {
      const client = new MonoCloudBackendNodeClient(baseOptions);
      expect(client).toBeInstanceOf(MonoCloudBackendNodeClient);
      expect(client).toBeInstanceOf(MonoCloudOidcBackendClient);
    });

    it('should accept an optional cache', () => {
      const cache: IIntrospectionCache = {
        get: vi.fn(),
        set: vi.fn(),
        delete: vi.fn(),
      };

      expect(
        () => new MonoCloudBackendNodeClient({ ...baseOptions, cache })
      ).not.toThrow();
    });
  });

  describe('validateAccessToken', () => {
    describe('input validation', () => {
      it.each([null, undefined, '', '   ', 42, {}])(
        'should throw if the access token is invalid (%p)',
        async token => {
          const client = new MonoCloudBackendNodeClient(baseOptions);

          await expect(
            client.validateAccessToken(token as never)
          ).rejects.toThrow(MonoCloudValidationError);
        }
      );
    });

    describe('JWT vs opaque dispatch', () => {
      it('should call validateJwtAccessToken when the token has three parts', async () => {
        const client = new MonoCloudBackendNodeClient(baseOptions);

        const jwtSpy = vi
          .spyOn(client, 'validateJwtAccessToken')
          .mockResolvedValue(buildClaims());
        const introspectSpy = vi
          .spyOn(client, 'introspectAccessToken')
          .mockResolvedValue(buildClaims());

        await client.validateAccessToken(jwtToken);

        expect(jwtSpy).toHaveBeenCalledTimes(1);
        expect(introspectSpy).not.toHaveBeenCalled();
      });

      it('should call introspectAccessToken when the token is opaque', async () => {
        const client = new MonoCloudBackendNodeClient(baseOptions);

        const jwtSpy = vi
          .spyOn(client, 'validateJwtAccessToken')
          .mockResolvedValue(buildClaims());
        const introspectSpy = vi
          .spyOn(client, 'introspectAccessToken')
          .mockResolvedValue(buildClaims());

        await client.validateAccessToken(opaqueToken);

        expect(introspectSpy).toHaveBeenCalledTimes(1);
        expect(jwtSpy).not.toHaveBeenCalled();
      });

      it('should call introspectAccessToken even for JWT tokens when introspectJwtTokens is true', async () => {
        const client = new MonoCloudBackendNodeClient({
          ...baseOptions,
          introspectJwtTokens: true,
        });

        const jwtSpy = vi
          .spyOn(client, 'validateJwtAccessToken')
          .mockResolvedValue(buildClaims());
        const introspectSpy = vi
          .spyOn(client, 'introspectAccessToken')
          .mockResolvedValue(buildClaims());

        await client.validateAccessToken(jwtToken);

        expect(introspectSpy).toHaveBeenCalledTimes(1);
        expect(jwtSpy).not.toHaveBeenCalled();
      });

      it('should forward validation options when dispatching to validateJwtAccessToken', async () => {
        const client = new MonoCloudBackendNodeClient(baseOptions);
        const jwtSpy = vi
          .spyOn(client, 'validateJwtAccessToken')
          .mockResolvedValue(buildClaims());

        await client.validateAccessToken(jwtToken, {
          scopes: ['read'],
          groups: ['admin'],
          validateCertificateBinding: true,
          clientCertificate: 'cert',
        });

        expect(jwtSpy).toHaveBeenCalledWith(jwtToken, {
          scopes: ['read'],
          groups: ['admin'],
          validateCertificateBinding: true,
          clientCertificate: 'cert',
        });
      });

      it.each([
        ['an opaque token', opaqueToken, false],
        ['a JWT when introspectJwtTokens is enabled', jwtToken, true],
      ])(
        'should reject %s with a validation error when introspection is not configured',
        async (_, token, introspectJwtTokens) => {
          const cache: IIntrospectionCache = {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
          };
          const client = new MonoCloudBackendNodeClient({
            tenantDomain: baseOptions.tenantDomain,
            audience: baseOptions.audience,
            introspectJwtTokens: introspectJwtTokens as boolean,
            cache,
          });

          const introspectSpy = vi.spyOn(client, 'introspectAccessToken');

          await expect(
            client.validateAccessToken(token as string)
          ).rejects.toThrow(
            new MonoCloudValidationError(
              'Token introspection is not configured'
            )
          );
          expect(introspectSpy).not.toHaveBeenCalled();
          expect(cache.get).not.toHaveBeenCalled();
        }
      );

      it('should forward validation options when dispatching to introspectAccessToken', async () => {
        const client = new MonoCloudBackendNodeClient(baseOptions);
        const introspectSpy = vi
          .spyOn(client, 'introspectAccessToken')
          .mockResolvedValue(buildClaims());

        await client.validateAccessToken(opaqueToken, {
          scopes: ['read'],
          groups: ['admin'],
          validateCertificateBinding: true,
          clientCertificate: 'cert',
        });

        expect(introspectSpy).toHaveBeenCalledWith(opaqueToken, {
          scopes: ['read'],
          groups: ['admin'],
          validateCertificateBinding: true,
          clientCertificate: 'cert',
        });
      });
    });

    describe('caching', () => {
      const getClient = (
        cache: IIntrospectionCache,
        overrides = {}
      ): MonoCloudBackendNodeClient =>
        new MonoCloudBackendNodeClient({
          ...baseOptions,
          cache,
          ...overrides,
        });

      it('should return cached claims when present and not expired', async () => {
        const cached = buildClaims({ exp: now() + 60 });
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(cached),
          set: vi.fn(),
          delete: vi.fn(),
        };

        const client = getClient(cache);

        const jwtSpy = vi.spyOn(client, 'validateJwtAccessToken');
        const introspectSpy = vi.spyOn(client, 'introspectAccessToken');

        const result = await client.validateAccessToken(opaqueToken);

        expect(result).toEqual(cached);
        expect(cache.get).toHaveBeenCalledWith(opaqueToken);
        expect(jwtSpy).not.toHaveBeenCalled();
        expect(introspectSpy).not.toHaveBeenCalled();
      });

      it('should return cached claims when the required scopes and groups are satisfied', async () => {
        const cached = buildClaims({
          exp: now() + 60,
          scope: 'read write',
          groups: ['admin'],
        });
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(cached),
          set: vi.fn(),
          delete: vi.fn(),
        };

        const client = getClient(cache);

        const introspectSpy = vi.spyOn(client, 'introspectAccessToken');

        const result = await client.validateAccessToken(opaqueToken, {
          scopes: ['read'],
          groups: ['admin'],
        });

        expect(result).toEqual(cached);
        expect(introspectSpy).not.toHaveBeenCalled();
      });

      it('should enforce required scopes on cached claims without re-introspecting', async () => {
        const cached = buildClaims({ exp: now() + 60, scope: 'read' });
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(cached),
          set: vi.fn(),
          delete: vi.fn(),
        };

        const client = getClient(cache);

        const introspectSpy = vi.spyOn(client, 'introspectAccessToken');

        const error = await client
          .validateAccessToken(opaqueToken, { scopes: ['write'] })
          .catch((e: unknown) => e);

        expect(error).toBeInstanceOf(MonoCloudTokenError);
        expect((error as MonoCloudTokenError).code).toBe('insufficient_scope');
        expect(introspectSpy).not.toHaveBeenCalled();
        expect(cache.set).not.toHaveBeenCalled();
      });

      it('should enforce required groups on cached claims without re-introspecting', async () => {
        const cached = buildClaims({ exp: now() + 60, groups: ['user'] });
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(cached),
          set: vi.fn(),
          delete: vi.fn(),
        };

        const client = getClient(cache);

        const introspectSpy = vi.spyOn(client, 'introspectAccessToken');

        const error = await client
          .validateAccessToken(opaqueToken, { groups: ['admin'] })
          .catch((e: unknown) => e);

        expect(error).toBeInstanceOf(MonoCloudTokenError);
        expect((error as MonoCloudTokenError).code).toBe('insufficient_groups');
        expect(introspectSpy).not.toHaveBeenCalled();
      });

      it('should validate certificate binding on cached claims when requested', async () => {
        const certificate = 'AQIDBAUGBwg=';
        const certificateBinary = atob(certificate);
        const certificateBytes = new Uint8Array(certificateBinary.length);

        for (let i = 0; i < certificateBinary.length; i++) {
          certificateBytes[i] = certificateBinary.charCodeAt(i);
        }

        const digest = await crypto.subtle.digest('SHA-256', certificateBytes);
        const certificateHash = btoa(
          String.fromCharCode(...new Uint8Array(digest))
        )
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');

        const cached = buildClaims({
          exp: now() + 60,
          cnf: { 'x5t#S256': certificateHash },
        });
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(cached),
          set: vi.fn(),
          delete: vi.fn(),
        };

        const client = getClient(cache);

        const introspectSpy = vi.spyOn(client, 'introspectAccessToken');

        const result = await client.validateAccessToken(opaqueToken, {
          validateCertificateBinding: true,
          clientCertificate: certificate,
        });

        expect(result).toEqual(cached);
        expect(introspectSpy).not.toHaveBeenCalled();
      });

      it('should throw when certificate binding is requested on a cache hit without a certificate', async () => {
        const cached = buildClaims({
          exp: now() + 60,
          cnf: { 'x5t#S256': 'hash' },
        });
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(cached),
          set: vi.fn(),
          delete: vi.fn(),
        };

        const client = getClient(cache);

        const introspectSpy = vi.spyOn(client, 'introspectAccessToken');

        const error = await client
          .validateAccessToken(opaqueToken, {
            validateCertificateBinding: true,
          })
          .catch((e: unknown) => e);

        expect(error).toBeInstanceOf(MonoCloudTokenError);
        expect((error as MonoCloudTokenError).code).toBe('invalid_token');
        expect((error as MonoCloudTokenError).message).toBe(
          'Client certificate is not present'
        );
        expect(introspectSpy).not.toHaveBeenCalled();
      });

      it('should ignore cached claims with no exp and continue validating', async () => {
        const cached = buildClaims({ exp: undefined });
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(cached),
          set: vi.fn(),
          delete: vi.fn(),
        };
        const client = getClient(cache);

        const freshClaims = buildClaims({ exp: now() + 120 });
        const introspectSpy = vi
          .spyOn(client, 'introspectAccessToken')
          .mockResolvedValue(freshClaims);

        const result = await client.validateAccessToken(opaqueToken);

        expect(introspectSpy).toHaveBeenCalledTimes(1);
        expect(result).toEqual(freshClaims);
      });

      it('should ignore cached claims when exp is not a number', async () => {
        const cached = buildClaims({ exp: 'soon' as never });
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(cached),
          set: vi.fn(),
          delete: vi.fn(),
        };
        const client = getClient(cache);

        const freshClaims = buildClaims({ exp: now() + 120 });
        const introspectSpy = vi
          .spyOn(client, 'introspectAccessToken')
          .mockResolvedValue(freshClaims);

        const result = await client.validateAccessToken(opaqueToken);

        expect(introspectSpy).toHaveBeenCalledTimes(1);
        expect(result).toEqual(freshClaims);
      });

      it('should revalidate when cached claims have expired beyond clock tolerance', async () => {
        const cached = buildClaims({ exp: now() - 3600 });
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(cached),
          set: vi.fn(),
          delete: vi.fn(),
        };
        const client = getClient(cache);

        const freshClaims = buildClaims({ exp: now() + 60 });
        const introspectSpy = vi
          .spyOn(client, 'introspectAccessToken')
          .mockResolvedValue(freshClaims);

        const result = await client.validateAccessToken(opaqueToken);

        expect(introspectSpy).toHaveBeenCalledTimes(1);
        expect(cache.set).toHaveBeenCalledWith(
          opaqueToken,
          freshClaims,
          freshClaims.exp
        );
        expect(result).toEqual(freshClaims);
      });

      it('should not store claims in cache when the result has no exp', async () => {
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(undefined),
          set: vi.fn(),
          delete: vi.fn(),
        };
        const client = getClient(cache);

        const fresh = buildClaims({ exp: undefined });
        vi.spyOn(client, 'introspectAccessToken').mockResolvedValue(fresh);

        await client.validateAccessToken(opaqueToken);

        expect(cache.set).not.toHaveBeenCalled();
      });

      it('should store freshly-validated claims in the cache', async () => {
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(undefined),
          set: vi.fn(),
          delete: vi.fn(),
        };
        const client = getClient(cache);

        const fresh = buildClaims({ exp: now() + 100 });
        vi.spyOn(client, 'introspectAccessToken').mockResolvedValue(fresh);

        await client.validateAccessToken(opaqueToken);

        expect(cache.set).toHaveBeenCalledWith(opaqueToken, fresh, fresh.exp);
      });

      it('should propagate errors thrown by cache.get', async () => {
        const cache: IIntrospectionCache = {
          get: vi.fn().mockRejectedValue(new Error('cache offline')),
          set: vi.fn(),
          delete: vi.fn(),
        };
        const client = getClient(cache);

        const introspectSpy = vi.spyOn(client, 'introspectAccessToken');

        await expect(client.validateAccessToken(opaqueToken)).rejects.toThrow(
          'cache offline'
        );
        expect(introspectSpy).not.toHaveBeenCalled();
        expect(cache.set).not.toHaveBeenCalled();
      });

      it('should not touch the cache for a locally-validated JWT', async () => {
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(undefined),
          set: vi.fn(),
          delete: vi.fn(),
        };
        const client = getClient(cache);

        const fresh = buildClaims({ exp: now() + 100 });
        const jwtSpy = vi
          .spyOn(client, 'validateJwtAccessToken')
          .mockResolvedValue(fresh);

        const result = await client.validateAccessToken(jwtToken);

        expect(jwtSpy).toHaveBeenCalledTimes(1);
        expect(cache.get).not.toHaveBeenCalled();
        expect(cache.set).not.toHaveBeenCalled();
        expect(result).toEqual(fresh);
      });
    });

    describe('without cache', () => {
      it('should not attempt to read or write a cache when none is configured', async () => {
        const client = new MonoCloudBackendNodeClient(baseOptions);

        const fresh = buildClaims();
        const jwtSpy = vi
          .spyOn(client, 'validateJwtAccessToken')
          .mockResolvedValue(fresh);

        const result = await client.validateAccessToken(jwtToken);

        expect(jwtSpy).toHaveBeenCalledTimes(1);
        expect(result).toEqual(fresh);
      });
    });
  });
});
