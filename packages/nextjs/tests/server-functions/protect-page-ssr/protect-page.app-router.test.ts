/* eslint-disable import/no-extraneous-dependencies */
import React, { JSX } from 'react';
import { NextRequest } from 'next/server';
import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';
import { MonoCloudNextClient } from '../../../src';
import {
  defaultSessionCookieValue,
  setSessionCookie,
  userWithGroupsSessionCookieValue,
} from '../../common-helper';

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

const Component =
  (assertUser = true) =>
  ({ user }: { user: unknown }): Promise<JSX.Element> => {
    if (assertUser) {
      expect(user).toEqual(defaultSessionCookieValue.user);
    }
    return Promise.resolve(React.createElement('div', {}, 'Great Success!!!'));
  };

describe('MonoCloud.protectPage() - App Router', () => {
  let monoCloud: MonoCloudNextClient;

  beforeEach(() => {
    req = new NextRequest('http://localhost:3000/');

    monoCloud = new MonoCloudNextClient();
  });

  afterEach(() => {
    req = undefined as unknown as NextRequest;
  });

  it('should render the component when session exists', async () => {
    await setSessionCookie(req);

    const protectedComponent = monoCloud.protectPage(Component());

    const componentResult = await protectedComponent({});

    expect(componentResult.type).toBe('div');
    expect(componentResult.props.children).toBe('Great Success!!!');
  });

  it('should render onAccessDenied if user is not authenticated', async () => {
    const protectedComponent = monoCloud.protectPage(Component(), {
      onAccessDenied: () =>
        React.createElement('div', {}, 'Access Denied CUSTOM'),
    });

    const componentResult = await protectedComponent({});

    expect(componentResult.type).toBe('div');
    expect(componentResult.props.children).toBe('Access Denied CUSTOM');
  });

  it('should redirect to sign in when there is no session', async () => {
    const protectedComponent = monoCloud.protectPage(Component());

    await protectedComponent({});
    expect(redirectCalled).toBe(
      'https://example.org/api/auth/signin?return_url=%2F'
    );
  });

  it('should set custom auth parameters for sign in', async () => {
    const protectedComponent = monoCloud.protectPage(Component(), {
      authParams: {
        acrValues: ['test'],
        prompt: 'none',
        authenticatorHint: 'apple',
        display: 'page',
        loginHint: 'username',
        maxAge: 3600,
        resource: 'https://api.example.org',
        scopes: 'openid profile',
        uiLocales: 'en',
      },
    });

    await protectedComponent({});
    expect(redirectCalled).toBe(
      'https://example.org/api/auth/signin?return_url=%2F&scope=openid+profile&resource=https%3A%2F%2Fapi.example.org&acr_values=test&display=page&prompt=none&authenticator_hint=apple&ui_locales=en&max_age=3600&login_hint=username'
    );
  });

  it('should pickup return url from x-monocloud-path header', async () => {
    req.headers.set('x-monocloud-path', '/custom');

    const protectedComponent = monoCloud.protectPage(Component());

    await protectedComponent({});
    expect(redirectCalled).toBe(
      'https://example.org/api/auth/signin?return_url=%2Fcustom'
    );
  });

  it('should pickup return url from options if configured', async () => {
    req.headers.set('x-monocloud-path', '/custom');

    const protectedComponent = monoCloud.protectPage(Component(), {
      returnUrl: '/overrides',
    });

    await protectedComponent({});
    expect(redirectCalled).toBe(
      'https://example.org/api/auth/signin?return_url=%2Foverrides'
    );
  });

  describe('groups', () => {
    it('should render the protected component if user belongs to any of the listed groups', async () => {
      await setSessionCookie(req, undefined, userWithGroupsSessionCookieValue);

      const protectedComponent = monoCloud.protectPage(Component(false), {
        groups: ['test'],
      });

      const componentResult = await protectedComponent({});

      expect(componentResult.type).toBe('div');
      expect(componentResult.props.children).toBe('Great Success!!!');
    });

    it('can customize the groups claim', async () => {
      await setSessionCookie(req, undefined, {
        ...defaultSessionCookieValue,
        user: { ...defaultSessionCookieValue.user, CUSTOM_GROUPS: ['test'] },
      });

      const protectedComponent = monoCloud.protectPage(Component(false), {
        groups: ['test'],
        groupsClaim: 'CUSTOM_GROUPS',
      });

      const componentResult = await protectedComponent({});

      expect(componentResult.type).toBe('div');
      expect(componentResult.props.children).toBe('Great Success!!!');
    });

    it('should not render the protected component if user does not belongs to any of the listed groups', async () => {
      await setSessionCookie(req, undefined, userWithGroupsSessionCookieValue);

      const protectedComponent = monoCloud.protectPage(Component(false), {
        groups: ['NOPE'],
      });

      const componentResult = await protectedComponent({});

      expect(componentResult).toBe('Access Denied');
    });

    it('can set custom onAccessDenied component', async () => {
      await setSessionCookie(req, undefined, userWithGroupsSessionCookieValue);

      const protectedComponent = monoCloud.protectPage(Component(false), {
        groups: ['NOPE'],
        onAccessDenied: () => 'Custom ERROR' as unknown as JSX.Element,
      });

      const componentResult = await protectedComponent({});

      expect(componentResult).toBe('Custom ERROR');
    });
  });
});
