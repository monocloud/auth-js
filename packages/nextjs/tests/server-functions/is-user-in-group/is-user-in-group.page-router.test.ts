/* eslint-disable import/no-extraneous-dependencies */
import { NextApiRequest, NextApiResponse } from 'next';
import { CookieJar } from 'tough-cookie';
import { describe, it, beforeEach, afterEach, expect } from 'vitest';
import { MonoCloudValidationError } from '@monocloud/auth-node-core';
import { MonoCloudNextClient } from '../../../src';
import {
  defaultSessionCookieValue,
  setSessionCookie,
  userWithGroupsSessionCookieValue,
} from '../../common-helper';
import {
  get,
  startNodeServer,
  stopNodeServer,
} from '../../page-router-helpers';

describe('MonoCloud.isUserInGroup() - Page Router', () => {
  let monoCloud: MonoCloudNextClient;
  beforeEach(() => {
    monoCloud = new MonoCloudNextClient();
  });

  afterEach(async () => {
    await stopNodeServer();
  });

  describe('With Request and Response (req, res)', () => {
    it('should return true if the user is in any of the specified groups', async () => {
      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        const result = await monoCloud.isUserInGroup(req, res, ['test']);

        res.end();

        expect(result).toBe(true);
      };

      const baseUrl = await startNodeServer(handler);

      const cookieJar = new CookieJar();

      await setSessionCookie(
        cookieJar,
        `${baseUrl}/`,
        userWithGroupsSessionCookieValue
      );

      await get(baseUrl, '/', cookieJar);
    });

    it('should return false if the user is in not in any of the specified groups', async () => {
      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        const result = await monoCloud.isUserInGroup(req, res, ['NOPE']);

        res.end();

        expect(result).toBe(false);
      };

      const baseUrl = await startNodeServer(handler);

      const cookieJar = new CookieJar();

      await setSessionCookie(
        cookieJar,
        `${baseUrl}/`,
        userWithGroupsSessionCookieValue
      );

      await get(baseUrl, '/', cookieJar);
    });

    it('can customize the groups claim', async () => {
      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        const result = await monoCloud.isUserInGroup(req, res, ['test'], {
          groupsClaim: 'CUSTOM_GROUPS',
        });

        res.end();

        expect(result).toBe(true);
      };

      const baseUrl = await startNodeServer(handler);

      const cookieJar = new CookieJar();

      await setSessionCookie(cookieJar, `${baseUrl}/`, {
        ...defaultSessionCookieValue,
        user: {
          ...defaultSessionCookieValue.user,
          CUSTOM_GROUPS: ['test'],
        },
      });

      await get(baseUrl, '/', cookieJar);
    });

    it('should return false if there is no session', async () => {
      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        const result = await monoCloud.isUserInGroup(req, res, ['NOPE']);

        res.end();

        expect(result).toBe(false);
      };

      const baseUrl = await startNodeServer(handler);

      await get(baseUrl, '/');
    });

    it('should throw if no groups are passed', async () => {
      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        try {
          await monoCloud.isUserInGroup(req, res, null as unknown as string[]);
          throw new Error();
        } catch (error) {
          expect(error).toBeInstanceOf(MonoCloudValidationError);
          expect((error as any).message).toBe(
            'Invalid parameters passed to isUserInGroup()'
          );
        }

        res.end();
      };

      const baseUrl = await startNodeServer(handler);

      await get(baseUrl, '/');
    });
  });
});
