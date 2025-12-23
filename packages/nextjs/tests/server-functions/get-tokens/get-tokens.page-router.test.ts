/* eslint-disable import/no-extraneous-dependencies */
import { NextApiRequest, NextApiResponse } from 'next';
import { CookieJar } from 'tough-cookie';
import { beforeEach, it, describe, expect, afterEach } from 'vitest';
import { MonoCloudNextClient, MonoCloudValidationError } from '../../../src';
import {
  defaultSessionCookieValue,
  setSessionCookie,
} from '../../common-helper';
import {
  defaultDiscovery,
  refreshedTokens,
  setupOp,
  tokenAndUserInfoEnabled,
} from '../../op-helpers.js';
import {
  get,
  startNodeServer,
  stopNodeServer,
} from '../../page-router-helpers';

describe('MonoCloud.getTokens() - Page Router', () => {
  let monoCloud: MonoCloudNextClient;
  beforeEach(() => {
    monoCloud = new MonoCloudNextClient();
  });

  afterEach(async () => {
    await stopNodeServer();
  });

  describe('With Request and Response (req, res)', () => {
    it('should return the tokens if the request is authenticated', async () => {
      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        const result = await monoCloud.getTokens(req, res);

        res.end();

        expect(result).toEqual({
          accessToken: defaultSessionCookieValue.accessTokens[0].accessToken,
          accessTokenExpiration:
            defaultSessionCookieValue.accessTokens[0].accessTokenExpiration,
          scopes: defaultSessionCookieValue.accessTokens[0].scopes,
          idToken: defaultSessionCookieValue.idToken,
          refreshToken: defaultSessionCookieValue.refreshToken,
          isExpired: false,
        });
      };

      const baseUrl = await startNodeServer(handler);

      const cookieJar = new CookieJar();

      await setSessionCookie(cookieJar, `${baseUrl}/`);

      await get(baseUrl, '/', cookieJar);
    });

    it('should throw if the request is not authenticated', async () => {
      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        try {
          await monoCloud.getTokens(req, res);
        } catch (error) {
          expect(error).toBeInstanceOf(MonoCloudValidationError);
          expect((error as any).message).toBe('Session does not exist');
        }

        res.end();
      };

      const baseUrl = await startNodeServer(handler);

      await get(baseUrl, '/');
    });

    it('should refresh the tokens when forceRefresh is true', async () => {
      await setupOp(defaultDiscovery, tokenAndUserInfoEnabled);

      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        const result = await monoCloud.getTokens(req, res, {
          forceRefresh: true,
        });

        res.end();

        expect(result).toEqual({
          ...refreshedTokens,
          scopes: 'openid profile email read:customer',
          accessTokenExpiration: expect.any(Number),
          isExpired: false,
        });
      };

      const baseUrl = await startNodeServer(handler);

      const cookieJar = new CookieJar();

      await setSessionCookie(cookieJar, `${baseUrl}/`);

      await get(baseUrl, '/', cookieJar);
    });
  });
});
