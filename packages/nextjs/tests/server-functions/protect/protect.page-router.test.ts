/* eslint-disable import/no-extraneous-dependencies */
import { NextApiRequest, NextApiResponse } from 'next';
import { describe, it, expect } from 'vitest';
import { MonoCloudNextClient } from '../../../src';
import {
  get,
  startNodeServer,
  stopNodeServer,
} from '../../page-router-helpers';

describe('protect() - Page Router', () => {
  it('should throw "protect() can only be used in App Router project"', async () => {
    const monoCloud = new MonoCloudNextClient();

    const getServerSideProps = async (
      _context: any
    ): Promise<{ props: { custom: string } }> => {
      await monoCloud.protect();
      return Promise.resolve({ props: { custom: 'prop' } });
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
        throw new Error();
      } catch (error: any) {
        expect(error.message).toBe(
          'protect() can only be used in App Router project'
        );
      }

      res.end();
    };

    const baseUrl = await startNodeServer(handler);

    await get(baseUrl, '/');

    await stopNodeServer();
  });
});
