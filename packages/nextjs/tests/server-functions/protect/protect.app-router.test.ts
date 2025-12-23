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

describe('protect() - App Router', () => {
  let monoCloud: MonoCloudNextClient;

  const Component = async (): Promise<JSX.Element> => {
    await monoCloud.protect();
    return React.createElement('div', {}, 'Great Success!!!');
  };

  beforeEach(() => {
    req = new NextRequest('http://localhost:3000/');
    redirectCalled = '';
    monoCloud = new MonoCloudNextClient();
  });

  afterEach(() => {
    req = undefined as unknown as NextRequest;
  });

  it('should render the component when session exists', async () => {
    await setSessionCookie(req);

    const componentResult: JSX.Element = await Component();

    expect(componentResult.type).toBe('div');
    expect(componentResult.props.children).toBe('Great Success!!!');
  });

  it('should render the component when the use is in the specified groups', async () => {
    await setSessionCookie(req, undefined, userWithGroupsSessionCookieValue);

    const ComponentWithGroups = async (): Promise<JSX.Element> => {
      await monoCloud.protect({ groups: ['test'] });
      return React.createElement('div', {}, 'Great Success!!!');
    };

    const componentResult: JSX.Element = await ComponentWithGroups();

    expect(componentResult.type).toBe('div');
    expect(componentResult.props.children).toBe('Great Success!!!');
  });

  it('can customize groups claim', async () => {
    await setSessionCookie(req, undefined, {
      ...defaultSessionCookieValue,
      user: { ...defaultSessionCookieValue.user, CUSTOM_GROUPS: ['test'] },
    });

    const ComponentWithGroups = async (): Promise<JSX.Element> => {
      await monoCloud.protect({
        groups: ['test'],
        groupsClaim: 'CUSTOM_GROUPS',
      });
      return React.createElement('div', {}, 'Great Success!!!');
    };

    const componentResult: JSX.Element = await ComponentWithGroups();

    expect(componentResult.type).toBe('div');
    expect(componentResult.props.children).toBe('Great Success!!!');
  });

  it('should redirect to sign in when there is no session', async () => {
    await Component();

    expect(redirectCalled).toBe(
      'https://example.org/api/auth/signin?return_url=%2F'
    );
  });

  it('should set custom auth parameters for sign in', async () => {
    const ComponentParams = async (): Promise<JSX.Element> => {
      await monoCloud.protect({
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
      return React.createElement('div', {}, 'Great Success!!!');
    };

    await ComponentParams();

    expect(redirectCalled).toBe(
      'https://example.org/api/auth/signin?return_url=%2F&max_age=3600&authenticator_hint=apple&scope=openid+profile&resource=https%3A%2F%2Fapi.example.org&display=page&ui_locales=en&acr_values=test&login_hint=username&prompt=none'
    );
  });

  it('should redirect to sign in when the user does not belong to any specified groups', async () => {
    await setSessionCookie(req, undefined, userWithGroupsSessionCookieValue);

    const ComponentWithGroups = async (): Promise<JSX.Element> => {
      await monoCloud.protect({ groups: ['NOPE'] });
      return React.createElement('div', {}, 'Great Success!!!');
    };

    await ComponentWithGroups();
    expect(redirectCalled).toBe(
      'https://example.org/api/auth/signin?return_url=%2F'
    );
  });

  it('should pickup return url from x-monocloud-path header', async () => {
    req.headers.set('x-monocloud-path', '/custom');

    await Component();
    await setSessionCookie(req, undefined, userWithGroupsSessionCookieValue);

    const ComponentWithGroups = async (): Promise<JSX.Element> => {
      await monoCloud.protect({ groups: ['NOPE'] });
      return React.createElement('div', {}, 'Great Success!!!');
    };
    await ComponentWithGroups();
    expect(redirectCalled).toBe(
      'https://example.org/api/auth/signin?return_url=%2Fcustom'
    );
  });

  it('should pickup return url from options if configured', async () => {
    req.headers.set('x-monocloud-path', '/custom');

    const ComponentWithRedirect = async (): Promise<JSX.Element> => {
      await monoCloud.protect({ returnUrl: '/overrides' });
      return React.createElement('div', {}, 'Great Success!!!');
    };

    await ComponentWithRedirect();
    expect(redirectCalled).toBe(
      'https://example.org/api/auth/signin?return_url=%2Foverrides'
    );
  });
});
