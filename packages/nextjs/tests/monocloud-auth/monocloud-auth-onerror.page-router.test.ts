/* eslint-disable import/no-extraneous-dependencies */
import { NextApiRequest, NextApiResponse } from 'next';
import { describe, it, expect } from 'vitest';
import { MonoCloudNextClient } from '../../src';
import { get, startNodeServer, stopNodeServer } from '../page-router-helpers';

describe('MonoCloud Auth - Page Router: onError', () => {
  it('can pass onError to monoCloudAuth() to handle errors', async () => {
    const authHandler = new MonoCloudNextClient().monoCloudAuth({
      onError: (_req: NextApiRequest, res: NextApiResponse) => {
        res.json({ custom: true });
        return Promise.resolve();
      },
    });

    const baseUrl = await startNodeServer(authHandler);

    const response = await get(
      baseUrl,
      '/api/auth/callback?code=123&state=321'
    );

    expect(response.status).toBe(200);
    expect(await response.getBody()).toEqual({ custom: true });

    await stopNodeServer();
  });
});
