/* eslint-disable prefer-destructuring */
/* eslint-disable @typescript-eslint/no-non-null-assertion */
import {
  getBoolean,
  getNumber,
  parseClientSecret,
} from '@monocloud/auth-core/internal';
import { DEFAULT_OPTIONS } from './defaults';
import { optionsSchema } from './validation';
import {
  ClientAuthMethod,
  MonoCloudValidationError,
} from '@monocloud/auth-core';
import { MonoCloudBackendNodeClientOptions } from '../types';

export const getOptions = (
  options?: Partial<MonoCloudBackendNodeClientOptions>,
  throwOnError = true
): MonoCloudBackendNodeClientOptions => {
  const MONOCLOUD_BACKEND_TENANT_DOMAIN =
    process.env.MONOCLOUD_BACKEND_TENANT_DOMAIN;
  const MONOCLOUD_BACKEND_AUDIENCE = process.env.MONOCLOUD_BACKEND_AUDIENCE;
  const MONOCLOUD_BACKEND_CLIENT_ID = process.env.MONOCLOUD_BACKEND_CLIENT_ID;
  const MONOCLOUD_BACKEND_CLIENT_SECRET =
    process.env.MONOCLOUD_BACKEND_CLIENT_SECRET;
  const MONOCLOUD_BACKEND_CLIENT_AUTH_METHOD =
    process.env.MONOCLOUD_BACKEND_CLIENT_AUTH_METHOD;
  const MONOCLOUD_BACKEND_TRUST_STORE_ID =
    process.env.MONOCLOUD_BACKEND_TRUST_STORE_ID;
  const MONOCLOUD_BACKEND_GROUPS_CLAIM =
    process.env.MONOCLOUD_BACKEND_GROUPS_CLAIM;
  const MONOCLOUD_BACKEND_GROUPS_MATCH_ALL =
    process.env.MONOCLOUD_BACKEND_GROUPS_MATCH_ALL;
  const MONOCLOUD_BACKEND_CLOCK_SKEW = process.env.MONOCLOUD_BACKEND_CLOCK_SKEW;
  const MONOCLOUD_BACKEND_CLOCK_TOLERANCE =
    process.env.MONOCLOUD_BACKEND_CLOCK_TOLERANCE;
  const MONOCLOUD_BACKEND_JWKS_CACHE_DURATION =
    process.env.MONOCLOUD_BACKEND_JWKS_CACHE_DURATION;
  const MONOCLOUD_BACKEND_METADATA_CACHE_DURATION =
    process.env.MONOCLOUD_BACKEND_METADATA_CACHE_DURATION;
  const MONOCLOUD_BACKEND_INTROSPECT_JWT_TOKENS =
    process.env.MONOCLOUD_BACKEND_INTROSPECT_JWT_TOKENS;
  const MONOCLOUD_BACKEND_RESPONSE_TIMEOUT =
    process.env.MONOCLOUD_BACKEND_RESPONSE_TIMEOUT;

  const opt: MonoCloudBackendNodeClientOptions = {
    tenantDomain: options?.tenantDomain ?? MONOCLOUD_BACKEND_TENANT_DOMAIN!,
    audience: options?.audience ?? MONOCLOUD_BACKEND_AUDIENCE!,
    clientId: options?.clientId ?? MONOCLOUD_BACKEND_CLIENT_ID!,
    clientSecret: parseClientSecret(
      options?.clientSecret ?? MONOCLOUD_BACKEND_CLIENT_SECRET
    ),
    groupOptions: {
      groupsClaim:
        options?.groupOptions?.groupsClaim ?? MONOCLOUD_BACKEND_GROUPS_CLAIM,
      matchAll:
        options?.groupOptions?.matchAll ??
        getBoolean(MONOCLOUD_BACKEND_GROUPS_MATCH_ALL),
    },
    clockSkew:
      options?.clockSkew ??
      getNumber(MONOCLOUD_BACKEND_CLOCK_SKEW) ??
      DEFAULT_OPTIONS.clockSkew,
    clockTolerance:
      options?.clockTolerance ??
      getNumber(MONOCLOUD_BACKEND_CLOCK_TOLERANCE) ??
      DEFAULT_OPTIONS.clockTolerance,
    clientAuthMethod:
      options?.clientAuthMethod ??
      (MONOCLOUD_BACKEND_CLIENT_AUTH_METHOD as ClientAuthMethod) ??
      DEFAULT_OPTIONS.clientAuthMethod,
    trustStoreId: options?.trustStoreId ?? MONOCLOUD_BACKEND_TRUST_STORE_ID,
    metadataResolver: options?.metadataResolver,
    jwksResolver: options?.jwksResolver,
    jwksCacheDuration:
      options?.jwksCacheDuration ??
      getNumber(MONOCLOUD_BACKEND_JWKS_CACHE_DURATION),
    metadataCacheDuration:
      options?.metadataCacheDuration ??
      getNumber(MONOCLOUD_BACKEND_METADATA_CACHE_DURATION),
    introspectJwtTokens:
      options?.introspectJwtTokens ??
      getBoolean(MONOCLOUD_BACKEND_INTROSPECT_JWT_TOKENS) ??
      DEFAULT_OPTIONS.introspectJwtTokens,
    responseTimeout:
      options?.responseTimeout ??
      getNumber(MONOCLOUD_BACKEND_RESPONSE_TIMEOUT) ??
      DEFAULT_OPTIONS.responseTimeout,
    fetcher: options?.fetcher,
    cache: options?.cache,
  };

  const { value, error } = optionsSchema.validate(opt, { abortEarly: false });

  const requiredEnv: Record<string, string> = {
    tenantDomain: 'MONOCLOUD_BACKEND_TENANT_DOMAIN',
    audience: 'MONOCLOUD_BACKEND_AUDIENCE',
  };

  if (error) {
    if (throwOnError) {
      throw new MonoCloudValidationError(error.details[0].message);
    }

    // eslint-disable-next-line no-console
    console.warn(
      'WARNING: One or more configuration options were not provided'
    );
    error.details.forEach(detail => {
      if (detail.context?.key && requiredEnv[detail.context.key]) {
        // eslint-disable-next-line no-console
        console.warn(
          `Missing: ${detail.context.key} - Set ${requiredEnv[detail.context.key]} environment variable in your .env file.`
        );
      }
    });
  }

  return value;
};
