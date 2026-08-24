/* eslint-disable import/no-extraneous-dependencies */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AccessTokenClaims,
  MonoCloudHttpError,
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

      it('should forward validation options and the client binding mode when dispatching to validateJwtAccessToken', async () => {
        const client = new MonoCloudBackendNodeClient({
          ...baseOptions,
          validateCertificateBinding: 'required',
        });
        const jwtSpy = vi
          .spyOn(client, 'validateJwtAccessToken')
          .mockResolvedValue(buildClaims());

        await client.validateAccessToken(jwtToken, {
          scopes: ['read'],
          groups: ['admin'],
          clientCertificate: 'cert',
        });

        expect(jwtSpy).toHaveBeenCalledWith(jwtToken, {
          scopes: ['read'],
          groups: ['admin'],
          validateCertificateBinding: 'required',
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

      it('should introspect the token without validation options', async () => {
        const client = new MonoCloudBackendNodeClient(baseOptions);
        const introspectSpy = vi
          .spyOn(client, 'introspectAccessToken')
          .mockResolvedValue(buildClaims({ scope: 'read' }));

        await client.validateAccessToken(opaqueToken, {
          scopes: ['read'],
        });

        expect(introspectSpy).toHaveBeenCalledWith(opaqueToken);
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

        const client = getClient(cache, {
          validateCertificateBinding: 'required',
        });

        const introspectSpy = vi.spyOn(client, 'introspectAccessToken');

        const result = await client.validateAccessToken(opaqueToken, {
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

        const client = getClient(cache, {
          validateCertificateBinding: 'required',
        });

        const introspectSpy = vi.spyOn(client, 'introspectAccessToken');

        const error = await client
          .validateAccessToken(opaqueToken)
          .catch((e: unknown) => e);

        expect(error).toBeInstanceOf(MonoCloudTokenError);
        expect((error as MonoCloudTokenError).code).toBe('invalid_token');
        expect((error as MonoCloudTokenError).message).toBe(
          'Client certificate is not present'
        );
        expect(introspectSpy).not.toHaveBeenCalled();
      });

      it('should serve cached claims that have no exp without re-introspecting', async () => {
        const cached = buildClaims({ exp: undefined });
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(cached),
          set: vi.fn(),
          delete: vi.fn(),
        };
        const client = getClient(cache);

        const introspectSpy = vi.spyOn(client, 'introspectAccessToken');

        const result = await client.validateAccessToken(opaqueToken);

        expect(introspectSpy).not.toHaveBeenCalled();
        expect(result).toEqual(cached);
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

      it('should cache claims without an exp for the introspection cache duration', async () => {
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(undefined),
          set: vi.fn(),
          delete: vi.fn(),
        };
        const client = getClient(cache);

        const fresh = buildClaims({ exp: undefined });
        vi.spyOn(client, 'introspectAccessToken').mockResolvedValue(fresh);

        await client.validateAccessToken(opaqueToken);

        expect(cache.set).toHaveBeenCalledWith(opaqueToken, fresh, now() + 300);
      });

      it('should cap the cache entry at the introspection cache duration for long-lived tokens', async () => {
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(undefined),
          set: vi.fn(),
          delete: vi.fn(),
        };
        const client = getClient(cache);

        const fresh = buildClaims({ exp: now() + 86400 });
        vi.spyOn(client, 'introspectAccessToken').mockResolvedValue(fresh);

        await client.validateAccessToken(opaqueToken);

        expect(cache.set).toHaveBeenCalledWith(opaqueToken, fresh, now() + 300);
      });

      it('should cap the cache entry at a custom introspection cache duration', async () => {
        const cache: IIntrospectionCache = {
          get: vi.fn().mockResolvedValue(undefined),
          set: vi.fn(),
          delete: vi.fn(),
        };
        const client = getClient(cache, { introspectionCacheDuration: 10 });

        const fresh = buildClaims({ exp: now() + 86400 });
        vi.spyOn(client, 'introspectAccessToken').mockResolvedValue(fresh);

        await client.validateAccessToken(opaqueToken);

        expect(cache.set).toHaveBeenCalledWith(opaqueToken, fresh, now() + 10);
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

      describe('inactive token caching', () => {
        const mkCache = (get: unknown = undefined): IIntrospectionCache => ({
          get: vi.fn().mockResolvedValue(get),
          set: vi.fn(),
          delete: vi.fn(),
        });

        const inactive = (): MonoCloudTokenError =>
          new MonoCloudTokenError(
            'Token is not active. The introspection endpoint returned active=false',
            'inactive_token'
          );

        it('should cache the inactive verdict and rethrow', async () => {
          const cache = mkCache();
          const client = getClient(cache);
          vi.spyOn(client, 'introspectAccessToken').mockRejectedValue(
            inactive()
          );

          await expect(
            client.validateAccessToken(opaqueToken)
          ).rejects.toMatchObject({ code: 'inactive_token' });

          expect(cache.set).toHaveBeenCalledWith(
            opaqueToken,
            { active: false, exp: now() + 300 },
            now() + 300
          );
        });

        it('should replay a cached inactive verdict without re-introspecting', async () => {
          const cache = mkCache({ active: false, exp: now() + 60 });
          const client = getClient(cache);
          const introspectSpy = vi.spyOn(client, 'introspectAccessToken');

          await expect(
            client.validateAccessToken(opaqueToken)
          ).rejects.toMatchObject({
            code: 'inactive_token',
            message:
              'Token is not active. A cached introspection result reported active=false',
          });

          expect(introspectSpy).not.toHaveBeenCalled();
        });

        it.each([
          ['expired', -1],
          ['without an expiry', undefined],
        ])(
          'should ignore a cached inactive verdict %s',
          async (_label, offset) => {
            const cache = mkCache({
              active: false,
              ...(offset === undefined ? {} : { exp: now() + offset }),
            });
            const client = getClient(cache);
            const claims = buildClaims();
            const introspectSpy = vi
              .spyOn(client, 'introspectAccessToken')
              .mockResolvedValue(claims);

            expect(await client.validateAccessToken(opaqueToken)).toEqual(
              claims
            );
            expect(introspectSpy).toHaveBeenCalledTimes(1);
          }
        );

        it.each([
          'insufficient_scope',
          'insufficient_groups',
          'invalid_token',
        ] as const)('should not cache a %s rejection', async code => {
          const cache = mkCache();
          const client = getClient(cache);
          vi.spyOn(client, 'introspectAccessToken').mockRejectedValue(
            new MonoCloudTokenError('nope', code)
          );

          await expect(
            client.validateAccessToken(opaqueToken)
          ).rejects.toBeInstanceOf(MonoCloudTokenError);

          expect(cache.set).not.toHaveBeenCalled();
        });

        it('should not cache a transport failure', async () => {
          const cache = mkCache();
          const client = getClient(cache);
          vi.spyOn(client, 'introspectAccessToken').mockRejectedValue(
            new MonoCloudHttpError('fetch failed')
          );

          await expect(
            client.validateAccessToken(opaqueToken)
          ).rejects.toBeInstanceOf(MonoCloudHttpError);

          expect(cache.set).not.toHaveBeenCalled();
        });

        it('should not read or write the cache when the duration is zero', async () => {
          const cache = mkCache();
          const client = getClient(cache, { introspectionCacheDuration: 0 });
          vi.spyOn(client, 'introspectAccessToken').mockRejectedValue(
            inactive()
          );

          await expect(
            client.validateAccessToken(opaqueToken)
          ).rejects.toMatchObject({ code: 'inactive_token' });

          expect(cache.get).not.toHaveBeenCalled();
          expect(cache.set).not.toHaveBeenCalled();
        });

        it('should honour a custom duration', async () => {
          const cache = mkCache();
          const client = getClient(cache, { introspectionCacheDuration: 5 });
          vi.spyOn(client, 'introspectAccessToken').mockRejectedValue(
            inactive()
          );

          await expect(
            client.validateAccessToken(opaqueToken)
          ).rejects.toMatchObject({ code: 'inactive_token' });

          expect(cache.set).toHaveBeenCalledWith(
            opaqueToken,
            { active: false, exp: now() + 5 },
            now() + 5
          );
        });
      });

      describe('client-level certificate binding mode', () => {
        const mkCache = (): IIntrospectionCache => ({
          get: vi.fn().mockResolvedValue(undefined),
          set: vi.fn(),
          delete: vi.fn(),
        });

        it('should reject a cnf-bearing token without a certificate by default', async () => {
          const client = getClient(mkCache());

          vi.spyOn(client, 'introspectAccessToken').mockResolvedValue(
            buildClaims({ exp: now() + 60, cnf: { 'x5t#S256': 'hash' } })
          );

          await expect(
            client.validateAccessToken(opaqueToken)
          ).rejects.toMatchObject({
            message: 'Client certificate is not present',
          });
        });

        it('should accept a token without a cnf claim by default', async () => {
          const client = getClient(mkCache());
          const claims = buildClaims({ exp: now() + 60 });

          vi.spyOn(client, 'introspectAccessToken').mockResolvedValue(claims);

          expect(await client.validateAccessToken(opaqueToken)).toEqual(claims);
        });

        it('should accept a token bound with a different confirmation method by default', async () => {
          const client = getClient(mkCache());
          const claims = buildClaims({
            exp: now() + 60,
            cnf: { jkt: 'dpop-thumbprint' },
          });

          vi.spyOn(client, 'introspectAccessToken').mockResolvedValue(claims);

          expect(await client.validateAccessToken(opaqueToken)).toEqual(claims);
        });

        it("should reject a token without a cnf claim when the mode is 'required'", async () => {
          const client = getClient(mkCache(), {
            validateCertificateBinding: 'required',
          });

          vi.spyOn(client, 'introspectAccessToken').mockResolvedValue(
            buildClaims({ exp: now() + 60 })
          );

          await expect(
            client.validateAccessToken(opaqueToken, {
              clientCertificate: 'AQIDBAUGBwg=',
            })
          ).rejects.toMatchObject({
            message:
              "Access token does not contain a 'cnf' (confirmation) claim for certificate binding",
          });
        });

        it("should accept a bound token with a mismatched certificate when the mode is 'dangerously_ignore'", async () => {
          const client = getClient(mkCache(), {
            validateCertificateBinding: 'dangerously_ignore',
          });
          const claims = buildClaims({
            exp: now() + 60,
            cnf: { 'x5t#S256': 'some-other-hash' },
          });

          vi.spyOn(client, 'introspectAccessToken').mockResolvedValue(claims);

          expect(
            await client.validateAccessToken(opaqueToken, {
              clientCertificate: 'AQIDBAUGBwg=',
            })
          ).toEqual(claims);
        });

        it('should apply the client mode to cache hits', async () => {
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

          await expect(
            client.validateAccessToken(opaqueToken)
          ).rejects.toMatchObject({
            message: 'Client certificate is not present',
          });

          expect(introspectSpy).not.toHaveBeenCalled();
        });
      });

      describe('caching regardless of the validation outcome', () => {
        const mkCache = (): IIntrospectionCache => ({
          get: vi.fn().mockResolvedValue(undefined),
          set: vi.fn(),
          delete: vi.fn(),
        });

        it('should cache the claims even when the scope check fails', async () => {
          const cache = mkCache();
          const client = getClient(cache);
          const claims = buildClaims({ exp: now() + 60, scope: 'read' });

          vi.spyOn(client, 'introspectAccessToken').mockResolvedValue(claims);

          await expect(
            client.validateAccessToken(opaqueToken, { scopes: ['write'] })
          ).rejects.toBeInstanceOf(MonoCloudTokenError);

          expect(cache.set).toHaveBeenCalledWith(
            opaqueToken,
            claims,
            claims.exp
          );
        });

        it('should cache the claims even when certificate binding fails', async () => {
          const cache = mkCache();
          const client = getClient(cache, {
            validateCertificateBinding: 'required',
          });
          const claims = buildClaims({ exp: now() + 60 });

          vi.spyOn(client, 'introspectAccessToken').mockResolvedValue(claims);

          await expect(
            client.validateAccessToken(opaqueToken)
          ).rejects.toBeInstanceOf(MonoCloudTokenError);

          expect(cache.set).toHaveBeenCalledWith(
            opaqueToken,
            claims,
            claims.exp
          );
        });

        it('should serve a later request from cache after an earlier one was rejected', async () => {
          const claims = buildClaims({ exp: now() + 60, scope: 'read' });
          const store = new Map<string, AccessTokenClaims>();
          const cache: IIntrospectionCache = {
            get: vi.fn(key => Promise.resolve(store.get(key))),
            set: vi.fn((key, value) => {
              store.set(key, value);
              return Promise.resolve();
            }),
            delete: vi.fn(),
          };

          const client = getClient(cache);
          const introspectSpy = vi
            .spyOn(client, 'introspectAccessToken')
            .mockResolvedValue(claims);

          await expect(
            client.validateAccessToken(opaqueToken, { scopes: ['write'] })
          ).rejects.toBeInstanceOf(MonoCloudTokenError);

          expect(
            await client.validateAccessToken(opaqueToken, { scopes: ['read'] })
          ).toEqual(claims);

          expect(introspectSpy).toHaveBeenCalledTimes(1);
        });

        it('should not introspect with scope or group options', async () => {
          const cache = mkCache();
          const client = getClient(cache);
          const introspectSpy = vi
            .spyOn(client, 'introspectAccessToken')
            .mockResolvedValue(buildClaims({ scope: 'read' }));

          await client.validateAccessToken(opaqueToken, { scopes: ['read'] });

          expect(introspectSpy).toHaveBeenCalledWith(opaqueToken);
        });
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
