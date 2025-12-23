/* eslint-disable import/no-extraneous-dependencies */
import { NextRequest, NextResponse } from 'next/server';
import { MonoCloudValidationError } from '@monocloud/auth-node-core';
import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';
import { MonoCloudNextClient } from '../../../src';
import {
  defaultSessionCookieValue,
  setSessionCookie,
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

describe('MonoCloud.isUserInGroup() - App Router', () => {
  let monoCloud: MonoCloudNextClient;
  beforeEach(async () => {
    req = new NextRequest('http://localhost:3000/');

    monoCloud = new MonoCloudNextClient();

    await setSessionCookie(req, undefined, {
      ...defaultSessionCookieValue,
      user: {
        ...defaultSessionCookieValue.user,
        groups: ['test'],
        CUSTOM_GROUPS: ['test'],
      },
    });
  });

  afterEach(() => {
    req = undefined as unknown as NextRequest;
  });

  describe('No params (<From Cookies>)', () => {
    it('should return true if the user is in any of the specified groups', async () => {
      const result = await monoCloud.isUserInGroup(['test']);

      expect(result).toBe(true);
    });

    it('should return false if the user is not in the specified groups', async () => {
      const result = await monoCloud.isUserInGroup(['NOPE']);

      expect(result).toBe(false);
    });

    it('can customize groups claim', async () => {
      const result = await monoCloud.isUserInGroup(['test'], {
        groupsClaim: 'CUSTOM_GROUPS',
      });

      expect(result).toBe(true);
    });
  });

  describe('With Request and Response (req, res)', () => {
    it('should return true if the user is in any of the specified groups', async () => {
      const res = new NextResponse();

      const result = await monoCloud.isUserInGroup(req, res, ['test']);

      expect(result).toBe(true);
    });

    it('should return false if the user is not in any of the specified groups', async () => {
      const res = new NextResponse();

      const result = await monoCloud.isUserInGroup(req, res, ['NOPE']);

      expect(result).toBe(false);
    });

    it('can customize groups claim', async () => {
      const res = new NextResponse();

      const result = await monoCloud.isUserInGroup(req, res, ['test'], {
        groupsClaim: 'CUSTOM_GROUPS',
      });

      expect(result).toBe(true);
    });
  });

  describe('With Request and Context (req, ctx)', () => {
    it('should return true if the user is in any of the specified groups', async () => {
      const result = await monoCloud.isUserInGroup(req, { params: {} }, [
        'test',
      ]);

      expect(result).toBe(true);
    });

    it('should return false if the user is not in any of the specified groups', async () => {
      const result = await monoCloud.isUserInGroup(req, { params: {} }, [
        'NOPE',
      ]);

      expect(result).toBe(false);
    });

    it('can customize the groups claim', async () => {
      const result = await monoCloud.isUserInGroup(
        req,
        { params: {} },
        ['test'],
        {
          groupsClaim: 'CUSTOM_GROUPS',
        }
      );

      expect(result).toBe(true);
    });
  });
});

describe('MonoCloud.isUserInGroup() - App Router (No session + No groups)', () => {
  let monoCloud: MonoCloudNextClient;
  beforeEach(() => {
    req = new NextRequest('http://localhost:3000/');

    monoCloud = new MonoCloudNextClient();
  });

  afterEach(() => {
    req = undefined as unknown as NextRequest;
  });

  describe('No params (<From Cookies>)', () => {
    it('should return false if there is no session', async () => {
      const result = await monoCloud.isUserInGroup(['test']);

      expect(result).toBe(false);
    });

    it('should throw if no groups are passed', async () => {
      try {
        await monoCloud.isUserInGroup(null as unknown as string[]);
        throw new Error();
      } catch (error) {
        expect(error).toBeInstanceOf(MonoCloudValidationError);
        expect((error as any).message).toBe(
          'Invalid parameters passed to isUserInGroup()'
        );
      }
    });

    it('can customize', async () => {});
  });

  describe('With Request and Response (req, res)', () => {
    it('should return false if there is no session', async () => {
      const res = new NextResponse();

      const result = await monoCloud.isUserInGroup(req, res, ['test']);

      expect(result).toBe(false);
    });

    it('should throw if no groups are passed', async () => {
      try {
        await monoCloud.isUserInGroup(
          req,
          new NextResponse(),
          null as unknown as string[]
        );
        throw new Error();
      } catch (error) {
        expect(error).toBeInstanceOf(MonoCloudValidationError);
        expect((error as any).message).toBe(
          'Invalid parameters passed to isUserInGroup()'
        );
      }
    });
  });

  describe('With Request and Context (req, ctx)', () => {
    it('should return false if there is no session', async () => {
      const result = await monoCloud.isUserInGroup(req, { params: {} }, [
        'test',
      ]);

      expect(result).toBe(false);
    });

    it('should throw if no groups are passed', async () => {
      try {
        await monoCloud.isUserInGroup(
          req,
          { params: {} },
          null as unknown as string[]
        );
        throw new Error();
      } catch (error) {
        expect(error).toBeInstanceOf(MonoCloudValidationError);
        expect((error as any).message).toBe(
          'Invalid parameters passed to isUserInGroup()'
        );
      }
    });
  });
});
