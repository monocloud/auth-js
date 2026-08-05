/* eslint-disable import/no-extraneous-dependencies */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AccessTokenClaims,
  MonoCloudOidcBackendClient,
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
