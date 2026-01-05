/* eslint-disable import/no-extraneous-dependencies */
import { NextRequest, NextResponse } from 'next/server';
import { beforeEach, it, describe, expect, afterEach, vi } from 'vitest';
import {
  GetTokensOptions,
  MonoCloudNextClient,
  MonoCloudValidationError,
} from '../../../src';
import {
  defaultSessionCookieValue,
  setSessionCookie,
} from '../../common-helper';
import {
  defaultDiscovery,
  refreshedTokens,
  setupOp,
  tokenAndUserInfoEnabled,
} from '../../op-helpers.js';

let req: NextRequest;

vi.mock('next/headers', () => {
  return {
    cookies: (): any => ({
      get: (name: string) => req.cookies.get(name),
      getAll: () => req.cookies.getAll(),
    }),
  };
});

describe('MonoCloud.getTokens() - App Router', () => {
  let monoCloud: MonoCloudNextClient;
  beforeEach(() => {
    req = new NextRequest('http://localhost:3000/');

    monoCloud = new MonoCloudNextClient();
  });

  afterEach(() => {
    req = undefined as unknown as NextRequest;
  });

  describe('No params (<From Cookies>)', () => {
    it('should return the tokens if the request is authenticated', async () => {
      await setSessionCookie(req);

      const result = await monoCloud.getTokens();

      expect(result).toEqual({
        accessToken: defaultSessionCookieValue.accessTokens[0].accessToken,
        accessTokenExpiration:
          defaultSessionCookieValue.accessTokens[0].accessTokenExpiration,
        scopes: defaultSessionCookieValue.accessTokens[0].scopes,
        idToken: defaultSessionCookieValue.idToken,
        refreshToken: defaultSessionCookieValue.refreshToken,
        isExpired: false,
      });
    });

    it('should throw an error if one of the argument is incorrect', async () => {
      await setSessionCookie(req);

      try {
        await monoCloud.getTokens(1 as unknown as GetTokensOptions);
        throw new Error();
      } catch (error) {
        expect(error).toBeInstanceOf(MonoCloudValidationError);
        expect((error as any).message).toBe(
          'Invalid parameters passed to getTokens()'
        );
      }
    });

    it('should throw if the request is not authenticated', async () => {
      try {
        await monoCloud.getTokens();
      } catch (error) {
        expect(error).toBeInstanceOf(MonoCloudValidationError);
        expect((error as any).message).toBe('Session does not exist');
      }
    });

    it('should refresh the tokens when forceRefresh is true', async () => {
      await setupOp(defaultDiscovery);

      await setSessionCookie(req);

      const result = await monoCloud.getTokens({ forceRefresh: true });

      expect(result).toEqual({
        ...refreshedTokens,
        scopes: 'openid profile email read:customer',
        accessTokenExpiration: expect.any(Number),
        isExpired: false,
      });
    });
  });

  describe('With Request and Response (req, res)', () => {
    it('should return the tokens if the request is authenticated', async () => {
      await setSessionCookie(req);

      const res = new NextResponse();

      const result = await monoCloud.getTokens(req, res);

      expect(result).toEqual({
        accessToken: defaultSessionCookieValue.accessTokens[0].accessToken,
        accessTokenExpiration:
          defaultSessionCookieValue.accessTokens[0].accessTokenExpiration,
        scopes: defaultSessionCookieValue.accessTokens[0].scopes,
        idToken: defaultSessionCookieValue.idToken,
        refreshToken: defaultSessionCookieValue.refreshToken,
        isExpired: false,
      });
    });

    it('should throw if the request is not authenticated', async () => {
      const res = new NextResponse();

      try {
        await monoCloud.getTokens(req, res);
      } catch (error) {
        expect(error).toBeInstanceOf(MonoCloudValidationError);
        expect((error as any).message).toBe('Session does not exist');
      }
    });

    it('should throw if the request is not authenticated (web request and response)', async () => {
      try {
        await monoCloud.getTokens(
          new Request('http://localhost:3000/'),
          new Response()
        );
      } catch (error) {
        expect(error).toBeInstanceOf(MonoCloudValidationError);
        expect((error as any).message).toBe('Session does not exist');
      }
    });

    it('should refresh the tokens when forceRefresh is true', async () => {
      await setupOp(defaultDiscovery);

      await setSessionCookie(req);

      const res = new NextResponse();

      const result = await monoCloud.getTokens(req, res, {
        forceRefresh: true,
      });

      expect(result).toEqual({
        ...refreshedTokens,
        scopes: 'openid profile email read:customer',
        accessTokenExpiration: expect.any(Number),
        isExpired: false,
      });
    });
  });

  describe('With Request (req)', () => {
    it('should return the tokens if the request is authenticated', async () => {
      await setSessionCookie(req);

      const result = await monoCloud.getTokens(req);

      expect(result).toEqual({
        accessToken: defaultSessionCookieValue.accessTokens[0].accessToken,
        accessTokenExpiration:
          defaultSessionCookieValue.accessTokens[0].accessTokenExpiration,
        scopes: defaultSessionCookieValue.accessTokens[0].scopes,
        idToken: defaultSessionCookieValue.idToken,
        refreshToken: defaultSessionCookieValue.refreshToken,
        isExpired: false,
      });
    });

    it('should throw if the request is not authenticated', async () => {
      try {
        await monoCloud.getTokens(req);
      } catch (error) {
        expect(error).toBeInstanceOf(MonoCloudValidationError);
        expect((error as any).message).toBe('Session does not exist');
      }
    });

    it('should refresh the tokens when forceRefresh is true', async () => {
      await setupOp(defaultDiscovery, tokenAndUserInfoEnabled);

      await setSessionCookie(req);

      const result = await monoCloud.getTokens(req, { forceRefresh: true });

      expect(result).toEqual({
        ...refreshedTokens,
        scopes: 'openid profile email read:customer',
        accessTokenExpiration: expect.any(Number),
        isExpired: false,
      });
    });
  });
});
