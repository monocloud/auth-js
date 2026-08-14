/* eslint-disable import/no-extraneous-dependencies */
import { vi } from 'vitest';
import { AccessTokenClaims, MonoCloudHttpError } from '@monocloud/auth-core';
import { MonoCloudBackendNodeClient } from '../../src/monocloud-backend-node-client';

export const baseOptions = {
  tenantDomain: 'https://example.monocloud.com',
  audience: 'https://api.example.com',
  clientId: 'client_id',
};

export const validClaims: AccessTokenClaims = {
  iss: baseOptions.tenantDomain,
  aud: baseOptions.audience,
  sub: 'sub',
  exp: 9999999999,
  iat: 0,
};

const addedEnvs = new Map<string, string>();

const addEnv = (env: string, value: string): void => {
  addedEnvs.set(env, value);
  process.env[env] = value;
};

export const setRequiredEnv = (): void => {
  addEnv('MONOCLOUD_BACKEND_TENANT_DOMAIN', baseOptions.tenantDomain);
  addEnv('MONOCLOUD_BACKEND_AUDIENCE', baseOptions.audience);
};

export const clearEnvs = (): void => {
  for (const key of addedEnvs.keys()) {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete process.env[key];
  }
  addedEnvs.clear();
};

export const mockValidateAccessToken = (
  resolved: AccessTokenClaims = validClaims
): ReturnType<typeof vi.spyOn> =>
  vi
    .spyOn(MonoCloudBackendNodeClient.prototype, 'validateAccessToken')
    .mockResolvedValue(resolved);

export const httpError = (status: number): MonoCloudHttpError =>
  new MonoCloudHttpError('boom', {
    status,
    statusText: '',
    headers: {},
    body: '',
  });

export const mockValidateAccessTokenRejection = (
  error: unknown
): ReturnType<typeof vi.spyOn> =>
  vi
    .spyOn(MonoCloudBackendNodeClient.prototype, 'validateAccessToken')
    .mockRejectedValue(error);
