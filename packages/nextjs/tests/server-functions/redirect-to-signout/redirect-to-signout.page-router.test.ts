/* eslint-disable import/no-extraneous-dependencies */
import { NextApiRequest, NextApiResponse } from 'next';
import { describe, it, expect } from 'vitest';
import { MonoCloudNextClient } from '../../../src';
import {
  get,
  startNodeServer,
  stopNodeServer,
} from '../../page-router-helpers';

describe('redirectToSignOut() - Page Router', () => {
  it('should throw "redirectToSignOut() can only be used in App Router project"', async () => {
    const monoCloud = new MonoCloudNextClient();

    // Simulate Page Router usage
    const getServerSideProps = async (_: any): Promise<any> => {
      await monoCloud.redirectToSignOut();
      return Promise.resolve({ props: {} });
    };

    const handler = async (
      req: NextApiRequest,
      res: NextApiResponse
    ): Promise<void> => {
      try {
        await getServerSideProps({
          req,
          res,
          query: req.query,
          resolvedUrl: req.url ?? '/',
        });
        // If we reach here, redirectToSignOut() didnt throw as expected
        throw new Error('Expected redirectToSignOut() to throw');
      } catch (error: any) {
        expect(error.message).toBe(
          'redirectToSignOut() can only be used in App Router project'
        );
      }

      res.end();
    };

    const baseUrl = await startNodeServer(handler);

    await get(baseUrl, '/');

    await stopNodeServer();
  });
});
