/* eslint-disable import/no-extraneous-dependencies */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as auth from '../src/initialize';
import { MonoCloudNextClient } from '../src/monocloud-next-client';

vi.mock('../src/monocloud-next-client', () => {
  const MockClient = vi.fn();

  MockClient.prototype.monoCloudAuth = vi
    .fn()
    .mockReturnValue('monoCloudAuth_result');
  MockClient.prototype.authMiddleware = vi
    .fn()
    .mockReturnValue('authMiddleware_result');
  MockClient.prototype.getSession = vi
    .fn()
    .mockResolvedValue('getSession_result');
  MockClient.prototype.getTokens = vi
    .fn()
    .mockResolvedValue('getTokens_result');
  MockClient.prototype.isAuthenticated = vi.fn().mockResolvedValue(true);
  MockClient.prototype.protect = vi.fn().mockResolvedValue('protect_result');
  MockClient.prototype.protectApi = vi
    .fn()
    .mockReturnValue('protectApi_result');
  MockClient.prototype.protectPage = vi
    .fn()
    .mockReturnValue('protectPage_result');
  MockClient.prototype.isUserInGroup = vi.fn().mockResolvedValue(true);
  MockClient.prototype.redirectToSignIn = vi
    .fn()
    .mockResolvedValue('redirectToSignIn_result');
  MockClient.prototype.redirectToSignOut = vi
    .fn()
    .mockResolvedValue('redirectToSignOut_result');

  return { MonoCloudNextClient: MockClient };
});

describe('monocloud-auth.ts exported functions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should delegate monoCloudAuth correctly', () => {
    const options = { onError: vi.fn() };
    const result = auth.monoCloudAuth(options);

    expect(MonoCloudNextClient.prototype.monoCloudAuth).toHaveBeenCalledWith(
      options
    );
    expect(result).toBe('monoCloudAuth_result');
  });

  it('should delegate authMiddleware correctly', () => {
    const req = {} as any;
    const evt = {} as any;
    const result = auth.authMiddleware(req, evt);

    expect(MonoCloudNextClient.prototype.authMiddleware).toHaveBeenCalledWith(
      req,
      evt
    );
    expect(result).toBe('authMiddleware_result');
  });

  it('should delegate getSession correctly', async () => {
    const req = {} as any;
    const res = {} as any;
    const result = await auth.getSession(req, res);

    expect(MonoCloudNextClient.prototype.getSession).toHaveBeenCalledWith(
      req,
      res
    );
    expect(result).toBe('getSession_result');
  });

  it('should delegate getTokens correctly', async () => {
    const req = {} as any;
    const result = await auth.getTokens(req);

    expect(MonoCloudNextClient.prototype.getTokens).toHaveBeenCalledWith(req);
    expect(result).toBe('getTokens_result');
  });

  it('should delegate isAuthenticated correctly', async () => {
    const result = await auth.isAuthenticated();

    expect(
      MonoCloudNextClient.prototype.isAuthenticated
    ).toHaveBeenCalledWith();
    expect(result).toBe(true);
  });

  it('should delegate protect correctly', async () => {
    const options = { returnUrl: '/home' };
    const result = await auth.protect(options);

    expect(MonoCloudNextClient.prototype.protect).toHaveBeenCalledWith(options);
    expect(result).toBe('protect_result');
  });

  it('should delegate protectApi correctly', () => {
    const handler = vi.fn();
    const options = { groups: ['admin'] };
    const result = auth.protectApi(handler, options);

    expect(MonoCloudNextClient.prototype.protectApi).toHaveBeenCalledWith(
      handler,
      options
    );
    expect(result).toBe('protectApi_result');
  });

  it('should delegate protectPage correctly', () => {
    const component = vi.fn();
    const result = auth.protectPage(component);

    expect(MonoCloudNextClient.prototype.protectPage).toHaveBeenCalledWith(
      component
    );
    expect(result).toBe('protectPage_result');
  });

  it('should delegate isUserInGroup correctly', async () => {
    const groups = ['admin'];
    const result = await auth.isUserInGroup(groups);

    expect(MonoCloudNextClient.prototype.isUserInGroup).toHaveBeenCalledWith(
      groups
    );
    expect(result).toBe(true);
  });

  it('should delegate redirectToSignIn correctly', async () => {
    const options = { returnUrl: '/dashboard' };
    const result = await auth.redirectToSignIn(options);

    expect(MonoCloudNextClient.prototype.redirectToSignIn).toHaveBeenCalledWith(
      options
    );
    expect(result).toBe('redirectToSignIn_result');
  });

  it('should delegate redirectToSignOut correctly', async () => {
    const options = { postLogoutRedirectUri: '/' };
    const result = await auth.redirectToSignOut(options);

    expect(
      MonoCloudNextClient.prototype.redirectToSignOut
    ).toHaveBeenCalledWith(options);
    expect(result).toBe('redirectToSignOut_result');
  });
});
