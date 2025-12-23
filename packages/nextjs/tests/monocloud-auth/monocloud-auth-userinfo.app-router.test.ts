/* eslint-disable import/no-extraneous-dependencies */
import { NextRequest } from 'next/server';
import { describe, beforeEach, afterEach, it, expect } from 'vitest';
import { MonoCloudNextClient } from '../../src';
import {
  noBodyDiscoverySuccess,
  noTokenAndUserInfo,
  setupOp,
} from '../op-helpers.js';
import { setSessionCookie } from '../common-helper';

describe('MonoCloud Auth - App Router: userinfo op error', () => {
  beforeEach(() => {
    process.env.MONOCLOUD_AUTH_REFETCH_USER_INFO = 'true';
  });

  afterEach(() => {
    process.env.MONOCLOUD_AUTH_REFETCH_USER_INFO = undefined;
  });

  it('userinfo endpoint should return 500 for authorization server errors', async () => {
    setupOp(noBodyDiscoverySuccess, noTokenAndUserInfo);

    const authHandler = new MonoCloudNextClient().monoCloudAuth();

    const req = new NextRequest('http://localhost:3000/api/auth/userinfo');

    await setSessionCookie(req);

    const response = await authHandler(req, {});

    expect(response.status).toBe(500);
  });
});
