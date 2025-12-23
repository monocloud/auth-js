/* eslint-disable import/no-extraneous-dependencies */
import { NextApiRequest, NextApiResponse } from 'next';
import { CookieJar } from 'tough-cookie';
import { describe, afterEach, beforeEach, it, expect } from 'vitest';
import { MonoCloudNextClient } from '../../../src';
import { setSessionCookie } from '../../common-helper';
import {
  get,
  startNodeServer,
  stopNodeServer,
} from '../../page-router-helpers';

describe('MonoCloud.isAuthenticated() - Page Router', () => {
  let monoCloud: MonoCloudNextClient;
  beforeEach(() => {
    monoCloud = new MonoCloudNextClient();
  });

  afterEach(async () => {
    await stopNodeServer();
  });

  describe('With Request and Response (req, res)', () => {
    it('should return true if the request is authenticated', async () => {
      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        const result = await monoCloud.isAuthenticated(req, res);

        res.end();

        expect(result).toBe(true);
      };

      const baseUrl = await startNodeServer(handler);

      const cookieJar = new CookieJar();
      await setSessionCookie(cookieJar, `${baseUrl}/`);

      await get(baseUrl, '/', cookieJar);
    });

    it('should return false if the request is not authenticated', async () => {
      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        const result = await monoCloud.isAuthenticated(req, res);

        res.end();

        expect(result).toBe(false);
      };

      const baseUrl = await startNodeServer(handler);

      await get(baseUrl, '/');
    });
  });
});
