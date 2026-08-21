/* eslint-disable import/no-extraneous-dependencies */
import { NextRequest, NextResponse } from 'next/server';
import { describe, it, expect, vi } from 'vitest';
import { MonoCloudNextClient } from '../../src';
import {
  backChannelLogoutSid,
  backChannelLogoutSub,
  createBackChannelLogoutToken,
  setupBackChannelLogoutOp,
} from '../op-helpers.js';

const defaultRoute = '/api/auth/backchannel-logout';

const backChannelLogoutRequest = (
  logoutToken?: string,
  { path = defaultRoute, method = 'POST' } = {}
): NextRequest => {
  const headers = new Headers();
  headers.set('content-type', 'application/x-www-form-urlencoded');

  return new NextRequest(
    new Request(`http://localhost:3000${path}`, {
      method,
      body:
        method === 'POST'
          ? new URLSearchParams(
              logoutToken ? { logout_token: logoutToken } : {}
            ).toString()
          : undefined,
      headers,
    })
  );
};

describe('Back-Channel Logout Handler - App Router', () => {
  it('should return 404 when no back-channel logout callback is configured', async () => {
    const authHandler = new MonoCloudNextClient().monoCloudAuth();

    const response = await authHandler(
      backChannelLogoutRequest(await createBackChannelLogoutToken()),
      { params: {} }
    );

    expect(response.status).toBe(404);
    expect(response.headers.get('cache-control')).toBe(
      'private, no-cache, no-store, must-revalidate, max-age=0'
    );
  });

  it('should perform a back-channel logout', async () => {
    setupBackChannelLogoutOp();

    const onBackChannelLogout = vi.fn();

    const authHandler = new MonoCloudNextClient({
      onBackChannelLogout,
    }).monoCloudAuth();

    const response = await authHandler(
      backChannelLogoutRequest(await createBackChannelLogoutToken()),
      { params: {} }
    );

    expect(response.status).toBe(204);
    expect(response.headers.get('cache-control')).toBe(
      'private, no-cache, no-store, must-revalidate, max-age=0'
    );
    expect(onBackChannelLogout).toHaveBeenCalledExactlyOnceWith(
      backChannelLogoutSub,
      backChannelLogoutSid
    );
  });

  it('should await an asynchronous back-channel logout callback', async () => {
    setupBackChannelLogoutOp();

    let completed = false;

    const authHandler = new MonoCloudNextClient({
      onBackChannelLogout: async (): Promise<void> => {
        await new Promise(resolve => setTimeout(resolve, 10));
        completed = true;
      },
    }).monoCloudAuth();

    const response = await authHandler(
      backChannelLogoutRequest(await createBackChannelLogoutToken()),
      { params: {} }
    );

    expect(response.status).toBe(204);
    expect(completed).toBe(true);
  });

  it('should not require a session cookie', async () => {
    setupBackChannelLogoutOp();

    const onBackChannelLogout = vi.fn();

    const authHandler = new MonoCloudNextClient({
      onBackChannelLogout,
    }).monoCloudAuth();

    const request = backChannelLogoutRequest(
      await createBackChannelLogoutToken()
    );

    expect(request.cookies.getAll()).toHaveLength(0);

    const response = await authHandler(request, { params: {} });

    expect(response.status).toBe(204);
    expect(onBackChannelLogout).toHaveBeenCalledOnce();
  });

  it('should honor a custom back-channel logout route', async () => {
    setupBackChannelLogoutOp();

    const onBackChannelLogout = vi.fn();

    const authHandler = new MonoCloudNextClient({
      onBackChannelLogout,
      routes: { backChannelLogout: '/api/auth/custom_backchannel_logout' },
    }).monoCloudAuth();

    const response = await authHandler(
      backChannelLogoutRequest(await createBackChannelLogoutToken(), {
        path: '/api/auth/custom_backchannel_logout',
      }),
      { params: {} }
    );

    expect(response.status).toBe(204);
    expect(onBackChannelLogout).toHaveBeenCalledOnce();
  });

  it('should return 404 on the default route when the route was overridden', async () => {
    const onBackChannelLogout = vi.fn();

    const authHandler = new MonoCloudNextClient({
      onBackChannelLogout,
      routes: { backChannelLogout: '/api/auth/custom_backchannel_logout' },
    }).monoCloudAuth();

    const response = await authHandler(
      backChannelLogoutRequest(await createBackChannelLogoutToken()),
      { params: {} }
    );

    expect(response.status).toBe(404);
    expect(onBackChannelLogout).not.toHaveBeenCalled();
  });

  ['GET', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].forEach(method => {
    it(`should return 405 on ${defaultRoute} for request type ${method}`, async () => {
      const onBackChannelLogout = vi.fn();

      const authHandler = new MonoCloudNextClient({
        onBackChannelLogout,
      }).monoCloudAuth();

      const response = await authHandler(
        backChannelLogoutRequest(undefined, { method }),
        { params: {} }
      );

      expect(response.status).toBe(405);
      expect(onBackChannelLogout).not.toHaveBeenCalled();
    });
  });

  it('should return 400 when the logout token is missing from the body', async () => {
    const onBackChannelLogout = vi.fn();

    const authHandler = new MonoCloudNextClient({
      onBackChannelLogout,
    }).monoCloudAuth();

    const response = await authHandler(backChannelLogoutRequest(), {
      params: {},
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'invalid_request',
      error_description: 'The logout token is missing or invalid.',
    });
    expect(response.headers.get('cache-control')).toBe(
      'private, no-cache, no-store, must-revalidate, max-age=0'
    );
    expect(onBackChannelLogout).not.toHaveBeenCalled();
  });

  [
    {
      name: 'is missing the back-channel logout event',
      claims: { events: {} },
    },
    {
      name: 'has no sub and no sid',
      claims: { sub: undefined, sid: undefined },
    },
    { name: 'contains a nonce', claims: { nonce: 'nonce' } },
  ].forEach(({ name, claims }) => {
    it(`should return 400 when the logout token ${name}`, async () => {
      setupBackChannelLogoutOp();

      const onBackChannelLogout = vi.fn();

      const authHandler = new MonoCloudNextClient({
        onBackChannelLogout,
      }).monoCloudAuth();

      const response = await authHandler(
        backChannelLogoutRequest(await createBackChannelLogoutToken(claims)),
        { params: {} }
      );

      expect(response.status).toBe(400);
      expect(onBackChannelLogout).not.toHaveBeenCalled();
    });
  });

  it('should return 500 when the back-channel logout callback throws', async () => {
    setupBackChannelLogoutOp();

    const authHandler = new MonoCloudNextClient({
      onBackChannelLogout: (): void => {
        throw new Error('session store unavailable');
      },
    }).monoCloudAuth();

    const response = await authHandler(
      backChannelLogoutRequest(await createBackChannelLogoutToken()),
      { params: {} }
    );

    expect(response.status).toBe(500);
  });

  it('should pass errors to a custom onError handler', async () => {
    const onError = vi.fn(() => NextResponse.json({ custom: true }));

    const authHandler = new MonoCloudNextClient({
      onBackChannelLogout: vi.fn(),
    }).monoCloudAuth({ onError });

    const response = await authHandler(backChannelLogoutRequest(), {
      params: {},
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ custom: true });
    expect(onError).toHaveBeenCalledOnce();
  });

  it('should not invoke onError on a successful back-channel logout', async () => {
    setupBackChannelLogoutOp();

    const onError = vi.fn();

    const authHandler = new MonoCloudNextClient({
      onBackChannelLogout: vi.fn(),
    }).monoCloudAuth({ onError });

    const response = await authHandler(
      backChannelLogoutRequest(await createBackChannelLogoutToken()),
      { params: {} }
    );

    expect(response.status).toBe(204);
    expect(onError).not.toHaveBeenCalled();
  });

  it('should return 500 for authorization server errors', async () => {
    setupBackChannelLogoutOp({ body: {} });

    const authHandler = new MonoCloudNextClient({
      onBackChannelLogout: vi.fn(),
    }).monoCloudAuth();

    const response = await authHandler(
      backChannelLogoutRequest(await createBackChannelLogoutToken()),
      { params: {} }
    );

    expect(response.status).toBe(500);
  });
});
