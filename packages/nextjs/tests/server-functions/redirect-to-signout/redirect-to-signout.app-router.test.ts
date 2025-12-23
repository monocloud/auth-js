/* eslint-disable import/no-extraneous-dependencies */
import { NextRequest } from 'next/server';
import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';
import { MonoCloudNextClient } from '../../../src';

let req: NextRequest;

vi.mock('next/headers', () => {
  return {
    headers: (): any => ({
      get: (name: string) => req.headers.get(name),
    }),
    cookies: (): any => ({
      get: (name: string) => req.cookies.get(name),
      getAll: () => req.cookies.getAll(),
    }),
  };
});

let redirectCalled = '';

vi.mock('next/navigation', () => {
  return {
    redirect: vi.fn((param: unknown) => {
      redirectCalled = param as string;
    }),
  };
});

describe('redirectToSignOut() - App Router', () => {
  let monoCloud: MonoCloudNextClient;

  beforeEach(() => {
    req = new NextRequest('http://localhost:3000/');
    redirectCalled = '';
    monoCloud = new MonoCloudNextClient();
  });

  afterEach(() => {
    req = undefined as unknown as NextRequest;
  });

  it('should redirect to sign out route without post_logout_url when no option is provided', async () => {
    await monoCloud.redirectToSignOut();

    expect(redirectCalled).toBe('https://example.org/api/auth/signout');
  });

  it('should append post_logout_redirect_uri when provided in options', async () => {
    await monoCloud.redirectToSignOut({
      postLogoutRedirectUri: 'https://example.org/goodbye',
    });

    expect(redirectCalled).toBe(
      'https://example.org/api/auth/signout?post_logout_url=https%3A%2F%2Fexample.org%2Fgoodbye'
    );
  });
});
