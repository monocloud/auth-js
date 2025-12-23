/* eslint-disable import/no-extraneous-dependencies */
import { NextRequest, NextResponse } from 'next/server';
import { describe, it, expect } from 'vitest';
import { MonoCloudNextClient } from '../../src';

describe('MonoCloud Auth - App Router: onError', () => {
  it('can pass onError to monoCloudAuth() to handle errors', async () => {
    const authHandler = new MonoCloudNextClient().monoCloudAuth({
      onError: () => Promise.resolve(NextResponse.json({ custom: true })),
    });

    const req = new NextRequest(
      'http://localhost:3000/api/auth/callback?code=123&state=321'
    );

    const response = await authHandler(req, {});

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ custom: true });
  });
});
