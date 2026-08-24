/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable @typescript-eslint/no-dynamic-delete */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MonoCloudValidationError } from '@monocloud/auth-core';
import { getOptions } from '../src/options/get-options';
import { MonoCloudBackendNodeClientOptions } from '../src/types';

describe('Configuration Options', () => {
  const addedEnvs = new Map<string, string>();

  const addEnv = (env: string, value: string): void => {
    addedEnvs.set(env, value);
    process.env[env] = value;
  };

  const setRequiredEnv = (): void => {
    addEnv('MONOCLOUD_BACKEND_TENANT_DOMAIN', 'https://issuer.monocloud.com');
    addEnv('MONOCLOUD_BACKEND_AUDIENCE', 'https://api.example.com');
  };

  const clearEnvs = (): void => {
    for (const key of addedEnvs.keys()) {
      delete process.env[key];
    }
    addedEnvs.clear();
  };

  afterEach(() => {
    clearEnvs();
  });

  it('should throw if required properties are not set', () => {
    expect(() => getOptions()).toThrow(MonoCloudValidationError);
  });

  it('should use environment variables when provided', () => {
    setRequiredEnv();
    addEnv('MONOCLOUD_BACKEND_CLIENT_ID', 'client_id');
    addEnv('MONOCLOUD_BACKEND_CLIENT_SECRET', 'client_secret');
    addEnv('MONOCLOUD_BACKEND_CLIENT_AUTH_METHOD', 'client_secret_basic');
    addEnv('MONOCLOUD_BACKEND_CLOCK_SKEW', '5');
    addEnv('MONOCLOUD_BACKEND_CLOCK_TOLERANCE', '120');
    addEnv('MONOCLOUD_BACKEND_JWKS_CACHE_DURATION', '60');
    addEnv('MONOCLOUD_BACKEND_METADATA_CACHE_DURATION', '90');
    addEnv('MONOCLOUD_BACKEND_INTROSPECT_JWT_TOKENS', 'true');
    addEnv('MONOCLOUD_BACKEND_RESPONSE_TIMEOUT', '3000');
    addEnv('MONOCLOUD_BACKEND_INTROSPECTION_CACHE_DURATION', '30');
    addEnv('MONOCLOUD_BACKEND_VALIDATE_CERTIFICATE_BINDING', 'required');
    addEnv('MONOCLOUD_BACKEND_GROUPS_CLAIM', 'roles');
    addEnv('MONOCLOUD_BACKEND_GROUPS_MATCH_ALL', 'true');
    addEnv('MONOCLOUD_BACKEND_TRUST_STORE_ID', 'trust-store-1');

    const options = getOptions();

    expect(options.tenantDomain).toBe('https://issuer.monocloud.com');
    expect(options.audience).toBe('https://api.example.com');
    expect(options.clientId).toBe('client_id');
    expect(options.clientSecret).toBe('client_secret');
    expect(options.clientAuthMethod).toBe('client_secret_basic');
    expect(options.trustStoreId).toBe('trust-store-1');
    expect(options.clockSkew).toBe(5);
    expect(options.clockTolerance).toBe(120);
    expect(options.jwksCacheDuration).toBe(60);
    expect(options.metadataCacheDuration).toBe(90);
    expect(options.introspectJwtTokens).toBe(true);
    expect(options.responseTimeout).toBe(3000);
    expect(options.introspectionCacheDuration).toBe(30);
    expect(options.validateCertificateBinding).toBe('required');
    expect(options.groupOptions?.groupsClaim).toBe('roles');
    expect(options.groupOptions?.matchAll).toBe(true);
  });

  it('should apply defaults when nothing is provided but required envs exist', () => {
    setRequiredEnv();

    const options = getOptions();

    expect(options.clockSkew).toBe(0);
    expect(options.clockTolerance).toBe(60);
    expect(options.clientAuthMethod).toBe('client_secret_post');
    expect(options.introspectJwtTokens).toBe(false);
    expect(options.responseTimeout).toBe(10000);
    expect(options.introspectionCacheDuration).toBe(300);
    expect(options.validateCertificateBinding).toBe('when_present');
  });

  it('should prefer constructor options over environment variables', () => {
    setRequiredEnv();
    addEnv('MONOCLOUD_BACKEND_CLIENT_ID', 'env_client_id');
    addEnv('MONOCLOUD_BACKEND_CLIENT_SECRET', 'env_client_secret');
    addEnv('MONOCLOUD_BACKEND_CLOCK_SKEW', '5');
    addEnv('MONOCLOUD_BACKEND_CLOCK_TOLERANCE', '120');
    addEnv('MONOCLOUD_BACKEND_JWKS_CACHE_DURATION', '60');
    addEnv('MONOCLOUD_BACKEND_METADATA_CACHE_DURATION', '90');
    addEnv('MONOCLOUD_BACKEND_INTROSPECT_JWT_TOKENS', 'true');
    addEnv('MONOCLOUD_BACKEND_RESPONSE_TIMEOUT', '3000');
    addEnv('MONOCLOUD_BACKEND_GROUPS_CLAIM', 'roles');
    addEnv('MONOCLOUD_BACKEND_GROUPS_MATCH_ALL', 'true');
    addEnv('MONOCLOUD_BACKEND_TRUST_STORE_ID', 'env-trust-store');

    const metadataResolver = vi.fn();
    const jwksResolver = vi.fn();

    const options = getOptions({
      tenantDomain: 'https://opt.monocloud.com',
      audience: 'https://api.opt.example.com',
      clientId: 'opt_client_id',
      clientSecret: 'opt_client_secret',
      clientAuthMethod: 'tls_client_auth',
      trustStoreId: 'opt-trust-store',
      metadataResolver,
      jwksResolver,
      clockSkew: 10,
      clockTolerance: 60,
      jwksCacheDuration: 30,
      metadataCacheDuration: 45,
      introspectJwtTokens: false,
      responseTimeout: 2000,
      introspectionCacheDuration: 15,
      validateCertificateBinding: 'dangerously_ignore',
      groupOptions: { groupsClaim: 'groups', matchAll: false },
    });

    expect(options.tenantDomain).toBe('https://opt.monocloud.com');
    expect(options.audience).toBe('https://api.opt.example.com');
    expect(options.clientId).toBe('opt_client_id');
    expect(options.clientSecret).toBe('opt_client_secret');
    expect(options.clientAuthMethod).toBe('tls_client_auth');
    expect(options.trustStoreId).toBe('opt-trust-store');
    expect(options.metadataResolver).toBe(metadataResolver);
    expect(options.jwksResolver).toBe(jwksResolver);
    expect(options.clockSkew).toBe(10);
    expect(options.clockTolerance).toBe(60);
    expect(options.jwksCacheDuration).toBe(30);
    expect(options.metadataCacheDuration).toBe(45);
    expect(options.introspectJwtTokens).toBe(false);
    expect(options.responseTimeout).toBe(2000);
    expect(options.introspectionCacheDuration).toBe(15);
    expect(options.validateCertificateBinding).toBe('dangerously_ignore');
    expect(options.groupOptions?.groupsClaim).toBe('groups');
    expect(options.groupOptions?.matchAll).toBe(false);
  });

  it('should accept a custom fetcher and cache via constructor options', () => {
    setRequiredEnv();

    const fetcher = vi.fn();
    const cache = {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    };

    const options = getOptions({ fetcher, cache });

    expect(options.fetcher).toBe(fetcher);
    expect(options.cache).toStrictEqual(cache);
  });

  it('should throw if the client auth method is invalid', () => {
    setRequiredEnv();

    expect(() =>
      getOptions({
        clientAuthMethod: 'not_a_valid_method' as never,
      })
    ).toThrow(MonoCloudValidationError);
  });

  it('should throw if tenantDomain is not a valid URL', () => {
    expect(() =>
      getOptions({
        tenantDomain: 'not-a-url',
        audience: 'https://api.example.com',
      })
    ).toThrow(MonoCloudValidationError);
  });

  it('should throw if clock skew is negative', () => {
    setRequiredEnv();

    expect(() => getOptions({ clockSkew: -1 })).toThrow(
      MonoCloudValidationError
    );
  });

  it('should throw if the response timeout is below the minimum', () => {
    setRequiredEnv();

    expect(() => getOptions({ responseTimeout: 999 })).toThrow(
      MonoCloudValidationError
    );
  });

  it('should throw if the certificate binding validation mode is invalid', () => {
    setRequiredEnv();

    expect(() =>
      // @ts-expect-error FOR TEST -- invalid mode
      getOptions({ validateCertificateBinding: 'nope' })
    ).toThrow(MonoCloudValidationError);
  });

  it('should throw if the introspection cache duration is negative', () => {
    setRequiredEnv();

    expect(() => getOptions({ introspectionCacheDuration: -1 })).toThrow(
      MonoCloudValidationError
    );
  });

  it('should throw if cache does not implement the required methods', () => {
    setRequiredEnv();

    expect(() => getOptions({ cache: {} as never })).toThrow(
      MonoCloudValidationError
    );
  });

  it('should warn instead of throwing when throwOnError is false and invalid config is provided', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const invalid: Partial<MonoCloudBackendNodeClientOptions> = {
      tenantDomain: 'not-a-url',
    };

    const options = getOptions(invalid, false);

    expect(options).toBeDefined();
    expect(warnSpy).toHaveBeenCalledWith(
      'WARNING: One or more configuration options were not provided'
    );
  });

  it('should not log a "Missing:" warning for keys that are not required envs when throwOnError=false', () => {
    setRequiredEnv();

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    expect(() => getOptions({ clockSkew: -1 }, false)).not.toThrow();

    const msgs = warnSpy.mock.calls.map(c => String(c[0]));
    expect(msgs).toContain(
      'WARNING: One or more configuration options were not provided'
    );
    expect(msgs.filter(m => m.startsWith('Missing: '))).toHaveLength(0);
  });

  it('should log per-key "Missing:" warnings for required envs when throwOnError=false', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    expect(() => getOptions(undefined, false)).not.toThrow();

    const msgs = warnSpy.mock.calls.map(c => String(c[0]));
    expect(msgs).toContain(
      'WARNING: One or more configuration options were not provided'
    );

    const missing = msgs.filter(m => m.startsWith('Missing: '));

    expect(missing).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          'Missing: tenantDomain - Set MONOCLOUD_BACKEND_TENANT_DOMAIN environment variable in your .env file.'
        ),
        expect.stringContaining(
          'Missing: audience - Set MONOCLOUD_BACKEND_AUDIENCE environment variable in your .env file.'
        ),
      ])
    );
  });

  it('should leave groupOptions.matchAll undefined when only groupsClaim is provided via env', () => {
    setRequiredEnv();
    addEnv('MONOCLOUD_BACKEND_GROUPS_CLAIM', 'roles');

    const options = getOptions();

    expect(options.groupOptions?.groupsClaim).toBe('roles');
    expect(options.groupOptions?.matchAll).toBeUndefined();
  });

  it('should parse a JWK client secret from a JSON string for private_key_jwt', () => {
    setRequiredEnv();
    addEnv('MONOCLOUD_BACKEND_CLIENT_ID', 'client_id');
    addEnv('MONOCLOUD_BACKEND_CLIENT_AUTH_METHOD', 'private_key_jwt');
    const jwk = {
      kty: 'RSA',
      kid: 'id',
      alg: 'RS256',
      n: 'n',
      e: 'AQAB',
      d: 'd',
    };
    addEnv('MONOCLOUD_BACKEND_CLIENT_SECRET', JSON.stringify(jwk));

    const options = getOptions();

    expect(options.clientAuthMethod).toBe('private_key_jwt');
    expect(options.clientSecret).toEqual(jwk);
  });

  it('should throw when clientAuthMethod is private_key_jwt but the client secret is a plain string', () => {
    setRequiredEnv();
    addEnv('MONOCLOUD_BACKEND_CLIENT_AUTH_METHOD', 'private_key_jwt');
    addEnv('MONOCLOUD_BACKEND_CLIENT_SECRET', 'plain-secret');

    expect(() => getOptions()).toThrow(MonoCloudValidationError);
    expect(() => getOptions()).toThrow(
      "clientSecret must be a valid JWK when clientAuthMethod is 'private_key_jwt'"
    );
  });
});
