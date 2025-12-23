/* eslint-disable import/no-extraneous-dependencies */
import { CookieJar } from 'tough-cookie';
import { describe, beforeEach, afterEach, it, expect } from 'vitest';
import { MonoCloudNextClient } from '../../src';
import { setSessionCookie } from '../common-helper';
import { get, startNodeServer, stopNodeServer } from '../page-router-helpers';
import {
  noBodyDiscoverySuccess,
  noTokenAndUserInfo,
  setupOp,
} from '../op-helpers.js';

describe('MonoCloud Auth - Page Router: userinfo op error', () => {
  beforeEach(() => {
    process.env.MONOCLOUD_AUTH_REFETCH_USER_INFO = 'true';
  });

  afterEach(() => {
    process.env.MONOCLOUD_AUTH_REFETCH_USER_INFO = undefined;
  });

  it('userinfo endpoint should return 500 for authorization server errors', async () => {
    setupOp(noBodyDiscoverySuccess, noTokenAndUserInfo);

    const authHandler = new MonoCloudNextClient().monoCloudAuth();

    const baseUrl = await startNodeServer(authHandler);

    const cookieJar = new CookieJar();

    await setSessionCookie(cookieJar, `${baseUrl}/api/auth/userinfo`);

    const response = await get(baseUrl, '/api/auth/userinfo', cookieJar);

    expect(response.status).toBe(500);

    await stopNodeServer();
  });
});
