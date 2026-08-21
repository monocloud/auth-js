/* eslint-disable import/no-extraneous-dependencies */
import { describe, beforeEach, afterEach, it, expect, vi } from 'vitest';
import { MonoCloudNextClient } from '../../src';
import { post, startNodeServer, stopNodeServer } from '../page-router-helpers';
import type { NextApiRequest, NextApiResponse } from 'next';
import {
  backChannelLogoutSid,
  backChannelLogoutSub,
  createBackChannelLogoutToken,
  setupBackChannelLogoutOp,
} from '../op-helpers.js';
import type { MonoCloudAuthOptions, MonoCloudOptions } from '../../src';
import type { TestPageRes } from '../common-helper';

const defaultRoute = '/api/auth/backchannel-logout';

describe('Back-Channel Logout Handler - Page Router', () => {
  let baseUrl: string;

  const startServer = async (
    options?: MonoCloudOptions,
    authOptions?: MonoCloudAuthOptions
  ): Promise<void> => {
    baseUrl = await startNodeServer(
      new MonoCloudNextClient(options).monoCloudAuth(authOptions)
    );
  };

  const postLogoutToken = (
    logoutToken?: string,
    path = defaultRoute
  ): Promise<TestPageRes> =>
    post(baseUrl, path, {
      body: new URLSearchParams(
        logoutToken ? { logout_token: logoutToken } : {}
      ).toString(),
    });

  beforeEach(() => {
    baseUrl = '';
  });

  afterEach(async () => {
    await stopNodeServer();
  });

  it('should return 404 when no back-channel logout callback is configured', async () => {
    await startServer();

    const response = await postLogoutToken(
      await createBackChannelLogoutToken()
    );

    expect(response.status).toBe(404);
  });

  it('should perform a back-channel logout', async () => {
    setupBackChannelLogoutOp();

    const onBackChannelLogout = vi.fn();

    await startServer({ onBackChannelLogout });

    const response = await postLogoutToken(
      await createBackChannelLogoutToken()
    );

    expect(response.status).toBe(204);
    expect(onBackChannelLogout).toHaveBeenCalledExactlyOnceWith(
      backChannelLogoutSub,
      backChannelLogoutSid
    );
  });

  it('should honor a custom back-channel logout route', async () => {
    setupBackChannelLogoutOp();

    const onBackChannelLogout = vi.fn();

    await startServer({
      onBackChannelLogout,
      routes: { backChannelLogout: '/api/auth/custom_backchannel_logout' },
    });

    const response = await postLogoutToken(
      await createBackChannelLogoutToken(),
      '/api/auth/custom_backchannel_logout'
    );

    expect(response.status).toBe(204);
    expect(onBackChannelLogout).toHaveBeenCalledOnce();
  });

  ['GET', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].forEach(method => {
    it(`should return 405 on ${defaultRoute} for request type ${method}`, async () => {
      const onBackChannelLogout = vi.fn();

      await startServer({ onBackChannelLogout });

      const response = await fetch(`${baseUrl}${defaultRoute}`, { method });

      expect(response.status).toBe(405);
      expect(onBackChannelLogout).not.toHaveBeenCalled();
    });
  });

  it('should return 400 when the logout token is missing from the body', async () => {
    const onBackChannelLogout = vi.fn();

    await startServer({ onBackChannelLogout });

    const response = await postLogoutToken();

    expect(response.status).toBe(400);
    expect(await response.getBody()).toEqual({
      error: 'invalid_request',
      error_description: 'The logout token is missing or invalid.',
    });
    expect(onBackChannelLogout).not.toHaveBeenCalled();
  });

  it('should return 400 for an invalid logout token', async () => {
    setupBackChannelLogoutOp();

    const onBackChannelLogout = vi.fn();

    await startServer({ onBackChannelLogout });

    const response = await postLogoutToken(
      await createBackChannelLogoutToken({ events: undefined })
    );

    expect(response.status).toBe(400);
    expect(onBackChannelLogout).not.toHaveBeenCalled();
  });

  it('should return 500 when the back-channel logout callback throws', async () => {
    setupBackChannelLogoutOp();

    await startServer({
      onBackChannelLogout: (): void => {
        throw new Error('session store unavailable');
      },
    });

    const response = await postLogoutToken(
      await createBackChannelLogoutToken()
    );

    expect(response.status).toBe(500);
  });

  it('should pass errors to a custom onError handler', async () => {
    const onError = vi.fn((_req: NextApiRequest, res: NextApiResponse) => {
      res.json({ custom: true });
    });

    await startServer({ onBackChannelLogout: vi.fn() }, { onError });

    const response = await postLogoutToken();

    expect(response.status).toBe(200);
    expect(await response.getBody()).toEqual({ custom: true });
    expect(onError).toHaveBeenCalledOnce();
  });

  it('should return 500 for authorization server errors', async () => {
    setupBackChannelLogoutOp({ body: {} });

    await startServer({ onBackChannelLogout: vi.fn() });

    const response = await postLogoutToken(
      await createBackChannelLogoutToken()
    );

    expect(response.status).toBe(500);
  });
});
