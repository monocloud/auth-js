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

describe('redirectToSignIn() - App Router', () => {
  let monoCloud: MonoCloudNextClient;

  beforeEach(() => {
    req = new NextRequest('http://localhost:3000/');
    redirectCalled = '';
    monoCloud = new MonoCloudNextClient();
  });

  afterEach(() => {
    req = undefined as unknown as NextRequest;
  });

  it('should not have return_url when no option is set', async () => {
    await monoCloud.redirectToSignIn();

    expect(redirectCalled).toBe('https://example.org/api/auth/signin');
  });

  it('should use options.returnUrl', async () => {
    await monoCloud.redirectToSignIn({ returnUrl: '/overrides' });

    expect(redirectCalled).toBe(
      'https://example.org/api/auth/signin?return_url=%2Foverrides'
    );
  });

  it('should set all configured auth parameters on the sign in url', async () => {
    await monoCloud.redirectToSignIn({
      acrValues: ['test'],
      prompt: 'none',
      authenticatorHint: 'apple',
      display: 'page',
      loginHint: 'username',
      maxAge: 3600,
      resource: ['https://api.example.org'],
      scopes: ['openid', 'profile'],
      uiLocales: 'en',
      returnUrl: '/overrides',
    });

    expect(redirectCalled).toBe(
      'https://example.org/api/auth/signin?return_url=%2Foverrides&max_age=3600&authenticator_hint=apple&scope=openid+profile&resource=https%3A%2F%2Fapi.example.org&display=page&ui_locales=en&acr_values=test&login_hint=username&prompt=none'
    );
  });
});
