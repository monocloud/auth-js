/* eslint-disable import/no-extraneous-dependencies */
import { CookieJar } from 'tough-cookie';
import { beforeEach, it, describe, expect, afterEach } from 'vitest';
import { NextApiRequest, NextApiResponse } from 'next';
import { MonoCloudNextClient } from '../../../src';
import {
  defaultDiscovery,
  noTokenAndUserInfo,
  setupOp,
} from '../../op-helpers.js';
import {
  defaultSessionCookieValue,
  setSessionCookie,
} from '../../common-helper';
import {
  get,
  startNodeServer,
  stopNodeServer,
} from '../../page-router-helpers';

describe('MonoCloud.getSession() - Page Router', () => {
  let monoCloud: MonoCloudNextClient;
  beforeEach(() => {
    setupOp(defaultDiscovery, noTokenAndUserInfo);

    monoCloud = new MonoCloudNextClient();
  });

  afterEach(async () => {
    await stopNodeServer();
  });

  it('should return undefined if there is no session (NextApiRequest, NextApiResponse)', async () => {
    const handler = async (
      req: NextApiRequest,
      res: NextApiResponse
    ): Promise<void> => {
      const session = await monoCloud.getSession(req, res);

      res.end();

      expect(session).toBeUndefined();
    };

    const baseUrl = await startNodeServer(handler);

    await get(baseUrl, '/');
  });

  it('should return the session of the current user (NextApiRequest, NextApiResponse)', async () => {
    const handler = async (
      req: NextApiRequest,
      res: NextApiResponse
    ): Promise<void> => {
      const session = await monoCloud.getSession(req, res);

      res.end();

      expect(session).toEqual(defaultSessionCookieValue);
    };

    const baseUrl = await startNodeServer(handler);

    const cookieJar = new CookieJar();

    await setSessionCookie(cookieJar, `${baseUrl}/`);

    await get(baseUrl, '/', cookieJar);
  });
});
