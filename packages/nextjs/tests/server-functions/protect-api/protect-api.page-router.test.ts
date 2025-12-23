/* eslint-disable import/no-extraneous-dependencies */
import { NextApiRequest, NextApiResponse } from 'next';
import { describe, it, expect, beforeEach } from 'vitest';
import { CookieJar } from 'tough-cookie';
import { MonoCloudNextClient } from '../../../src';
import {
  get,
  startNodeServer,
  stopNodeServer,
} from '../../page-router-helpers';
import {
  defaultSessionCookieValue,
  setSessionCookie,
  userWithGroupsSessionCookieValue,
} from '../../common-helper';

describe('MonoCloud.protectApi() - Page Router', () => {
  let monoCloud: MonoCloudNextClient;

  beforeEach(() => {
    monoCloud = new MonoCloudNextClient();
  });

  it('should return unauthorized for requests with no session', async () => {
    const api = monoCloud.protectApi(
      (_req: NextApiRequest, res: NextApiResponse<object>) =>
        res.json({ success: true })
    );

    const baseUrl = await startNodeServer(api);

    const res = await get(baseUrl, '/api/someroute');

    await stopNodeServer();

    expect(res.status).toBe(401);
    expect(await res.getBody()).toEqual({
      message: 'unauthorized',
    });
  });

  it('can cusotmize onAccessDenied handler', async () => {
    const api = monoCloud.protectApi(
      (_req: NextApiRequest, res: NextApiResponse<object>) =>
        res.json({ success: true }),
      { onAccessDenied: (_req, res) => res.status(200).json({ custom: true }) }
    );

    const baseUrl = await startNodeServer(api);

    const res = await get(baseUrl, '/api/someroute');

    await stopNodeServer();

    expect(res.status).toBe(200);
    expect(await res.getBody()).toEqual({
      custom: true,
    });
  });

  it('should allow requests with session', async () => {
    const api = monoCloud.protectApi(
      (_req: NextApiRequest, res: NextApiResponse<object>) =>
        res.json({ success: true })
    );

    const baseUrl = await startNodeServer(api);

    const cookieJar = new CookieJar();

    await setSessionCookie(cookieJar, `${baseUrl}/api/someroute`);

    const res = await get(baseUrl, '/api/someroute', cookieJar);

    await stopNodeServer();

    expect(res.status).toBe(200);
    expect(await res.getBody()).toEqual({
      success: true,
    });
  });

  describe('groups', () => {
    it('should allow access to api if user belongs to any of the listed groups', async () => {
      const api = monoCloud.protectApi(
        (_req: NextApiRequest, res: NextApiResponse<object>) =>
          res.json({ success: true }),
        { groups: ['test'] }
      );

      const baseUrl = await startNodeServer(api);

      const cookieJar = new CookieJar();

      await setSessionCookie(
        cookieJar,
        `${baseUrl}/api/someroute`,
        userWithGroupsSessionCookieValue
      );

      const res = await get(baseUrl, '/api/someroute', cookieJar);

      await stopNodeServer();

      expect(res.status).toBe(200);
      expect(await res.getBody()).toEqual({
        success: true,
      });
    });

    it('can customize the groups claim', async () => {
      const api = monoCloud.protectApi(
        (_req: NextApiRequest, res: NextApiResponse<object>) =>
          res.json({ success: true }),
        { groups: ['test'], groupsClaim: 'CUSTOM_GROUPS' }
      );

      const baseUrl = await startNodeServer(api);

      const cookieJar = new CookieJar();

      await setSessionCookie(cookieJar, `${baseUrl}/api/someroute`, {
        ...defaultSessionCookieValue,
        user: { ...defaultSessionCookieValue.user, CUSTOM_GROUPS: ['test'] },
      });

      const res = await get(baseUrl, '/api/someroute', cookieJar);

      await stopNodeServer();

      expect(res.status).toBe(200);
      expect(await res.getBody()).toEqual({
        success: true,
      });
    });

    it('should not allow access to api if user does not belongs to any of the listed groups', async () => {
      const api = monoCloud.protectApi(
        (_req: NextApiRequest, res: NextApiResponse<object>) =>
          res.json({ success: true }),
        { groups: ['NOPE'] }
      );

      const baseUrl = await startNodeServer(api);

      const cookieJar = new CookieJar();

      await setSessionCookie(
        cookieJar,
        `${baseUrl}/api/someroute`,
        userWithGroupsSessionCookieValue
      );

      const res = await get(baseUrl, '/api/someroute', cookieJar);

      await stopNodeServer();

      expect(res.status).toBe(403);
      expect(await res.getBody()).toEqual({
        message: 'forbidden',
      });
    });

    it('can set custom onAccessDenied handler', async () => {
      const api = monoCloud.protectApi(
        (_req: NextApiRequest, res: NextApiResponse<object>) =>
          res.json({ success: true }),
        {
          groups: ['NOPE'],
          onAccessDenied: (_req, res) => res.json({ custom: true }),
        }
      );

      const baseUrl = await startNodeServer(api);

      const cookieJar = new CookieJar();

      await setSessionCookie(
        cookieJar,
        `${baseUrl}/api/someroute`,
        userWithGroupsSessionCookieValue
      );

      const res = await get(baseUrl, '/api/someroute', cookieJar);

      await stopNodeServer();

      expect(res.status).toBe(200);
      expect(await res.getBody()).toEqual({
        custom: true,
      });
    });
  });
});
