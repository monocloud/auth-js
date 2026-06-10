/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable @typescript-eslint/no-dynamic-delete */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { getOptions } from '../src/options/get-options';
import { MonoCloudOptionsBase } from '../src';
import { MonoCloudValidationError } from '@monocloud/auth-core';

describe('Configuration Options', () => {
  const addedEnvs = new Map<string, string>();

  const addEnv = (env: string, value: string): void => {
    addedEnvs.set(env, value);
    process.env[env] = value;
  };

  const setRequiredEnv = (): void => {
    addEnv('MONOCLOUD_AUTH_APP_URL', 'https://example.com');
    addEnv('MONOCLOUD_AUTH_CLIENT_ID', 'client_id');
    addEnv('MONOCLOUD_AUTH_CLIENT_SECRET', 'client_secret');
    addEnv('MONOCLOUD_AUTH_SCOPES', 'openid profile'); // Scopes are not required. Added this line for code coverage.
    addEnv('MONOCLOUD_AUTH_TENANT_DOMAIN', 'https://issuer.monocloud.com');
    addEnv('MONOCLOUD_AUTH_COOKIE_SECRET', 'htmlisnotaprogramminglanguage!!!');
  };

  const clearEnvs = (): void => {
    addedEnvs.forEach(k => {
      delete process.env[k];
    });

    addedEnvs.clear();
  };

  afterEach(() => {
    clearEnvs();
    vi.restoreAllMocks();
  });

  it('should throw if the required properties are not set up', () => {
    expect(() => getOptions()).toThrow(MonoCloudValidationError);
  });

  it('should be able to configure id token claims filter', () => {
    setRequiredEnv();
    addEnv(
      'MONOCLOUD_AUTH_FILTERED_ID_TOKEN_CLAIMS',
      'c_hash at_hash mono_cloud'
    );

    const options = getOptions();
    expect(options).toBeDefined();

    expect(options.filteredIdTokenClaims).toEqual([
      'c_hash',
      'at_hash',
      'mono_cloud',
    ]);
  });

  it('should default clockSkew to 0 and clockTolerance to 60', () => {
    setRequiredEnv();

    const options = getOptions();

    expect(options.clockSkew).toBe(0);
    expect(options.clockTolerance).toBe(60);
  });

  it('should resolve clockSkew and clockTolerance from environment variables', () => {
    setRequiredEnv();
    addEnv('MONOCLOUD_AUTH_CLOCK_SKEW', '15');
    addEnv('MONOCLOUD_AUTH_CLOCK_TOLERANCE', '90');

    const options = getOptions();

    expect(options.clockSkew).toBe(15);
    expect(options.clockTolerance).toBe(90);
  });

  it('should resolve clockSkew and clockTolerance from explicit options', () => {
    setRequiredEnv();

    const options = getOptions({ clockSkew: 5, clockTolerance: 30 });

    expect(options.clockSkew).toBe(5);
    expect(options.clockTolerance).toBe(30);
  });

  it('should default groupsClaim to "groups"', () => {
    setRequiredEnv();

    const options = getOptions();

    expect(options.groupsClaim).toBe('groups');
  });

  it('should resolve groupsClaim from environment variables', () => {
    setRequiredEnv();
    addEnv('MONOCLOUD_AUTH_GROUPS_CLAIM', 'custom_groups');

    const options = getOptions();

    expect(options.groupsClaim).toBe('custom_groups');
  });

  it('should resolve groupsClaim from explicit options', () => {
    setRequiredEnv();
    addEnv('MONOCLOUD_AUTH_GROUPS_CLAIM', 'env_groups');

    const options = getOptions({ groupsClaim: 'option_groups' });

    expect(options.groupsClaim).toBe('option_groups');
  });

  it('should throw if clockSkew is negative', () => {
    setRequiredEnv();

    expect(() => getOptions({ clockSkew: -1 })).toThrow(
      MonoCloudValidationError
    );
  });

  it('should throw if clockTolerance is negative', () => {
    setRequiredEnv();

    expect(() => getOptions({ clockTolerance: -1 })).toThrow(
      MonoCloudValidationError
    );
  });

  it('should throw if the resource are not a valid url', () => {
    setRequiredEnv();
    addEnv('MONOCLOUD_AUTH_RESOURCE', 'ap1 api2');

    expect(() => getOptions()).toThrow(MonoCloudValidationError);
    expect(() => getOptions()).toThrowError(
      'Resource must be a valid URL without query or hash parameters'
    );
  });

  it('should throw if the scope does not have openid', () => {
    setRequiredEnv();
    addEnv('MONOCLOUD_AUTH_SCOPES', 'abc');

    expect(() => getOptions()).toThrow(MonoCloudValidationError);
    expect(() => getOptions()).toThrowError('Scope must contain openid');
  });

  it('should throw if the scope is empty', () => {
    setRequiredEnv();
    addEnv('MONOCLOUD_AUTH_SCOPES', '    ');

    expect(() => getOptions()).toThrow(MonoCloudValidationError);
    expect(() => getOptions()).toThrowError(
      'Scopes must be a space-separated string'
    );
  });

  it('should throw if the resource have query params or hash', () => {
    setRequiredEnv();
    addEnv(
      'MONOCLOUD_AUTH_RESOURCE',
      'https://example.com?query=1 https://example.com#hash=1'
    );

    expect(() => getOptions()).toThrow(MonoCloudValidationError);
    expect(() => getOptions()).toThrowError(
      'Resource must be a valid URL without query or hash parameters'
    );
  });

  it('should be able to set resources', () => {
    setRequiredEnv();
    addEnv(
      'MONOCLOUD_AUTH_RESOURCE',
      'https://example.com https://api.example.com'
    );

    const options = getOptions();
    expect(options.defaultAuthParams.resource).toEqual(
      'https://example.com https://api.example.com'
    );
  });

  it('should not throw MonoCloudValidationError when throwOnError=false and invalid config is provided.', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const invalidOptions: Partial<MonoCloudOptionsBase> = {
      defaultAuthParams: {
        resource: 'mono cloud',
      },
    };

    const options = getOptions(invalidOptions, false);

    expect(options).toBeDefined();

    expect(warnSpy).toHaveBeenCalledWith(
      'WARNING: One or more configuration options were not provided for MonoCloudClient.'
    );
  });

  it('should log per-key "Missing:" warnings for required envs when throwOnError=false', () => {
    delete process.env.MONOCLOUD_AUTH_TENANT_DOMAIN;
    delete process.env.MONOCLOUD_AUTH_CLIENT_ID;
    delete process.env.MONOCLOUD_AUTH_CLIENT_SECRET;
    delete process.env.MONOCLOUD_AUTH_APP_URL;
    delete process.env.MONOCLOUD_AUTH_COOKIE_SECRET;

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    expect(() => getOptions(undefined, false)).not.toThrow();

    const msgs = warnSpy.mock.calls.map(c => String(c[0]));
    expect(msgs).toContain(
      'WARNING: One or more configuration options were not provided for MonoCloudClient.'
    );

    const missing = msgs.filter(m => m.startsWith('Missing: '));

    expect(missing.length).toBe(5);
    expect(missing).toEqual(
      expect.arrayContaining([
        expect.stringMatching(
          'Missing: clientId - Set MONOCLOUD_AUTH_CLIENT_ID environment variable in your .env file.'
        ),
        expect.stringMatching(
          'Missing: clientSecret - Set MONOCLOUD_AUTH_CLIENT_SECRET environment variable in your .env file.'
        ),
        expect.stringMatching(
          'Missing: tenantDomain - Set MONOCLOUD_AUTH_TENANT_DOMAIN environment variable in your .env file.'
        ),
        expect.stringMatching(
          'Missing: cookieSecret - Set MONOCLOUD_AUTH_COOKIE_SECRET environment variable in your .env file.'
        ),
        expect.stringMatching(
          'Missing: appUrl - Set MONOCLOUD_AUTH_APP_URL environment variable in your .env file.'
        ),
      ])
    );
  });
});
