/* eslint-disable import/no-extraneous-dependencies */
import { NextRequest, NextResponse } from 'next/server';
import { vi, describe, afterEach, beforeEach, it, expect } from 'vitest';
import { MonoCloudNextClient } from '../../../src';
import { setSessionCookie } from '../../common-helper';

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

describe('MonoCloud.isAuthenticated() - App Router', () => {
  let monoCloud: MonoCloudNextClient;
  beforeEach(() => {
    req = new NextRequest('http://localhost:3000/');

    monoCloud = new MonoCloudNextClient();
  });

  afterEach(() => {
    req = undefined as unknown as NextRequest;
  });

  describe('No params (<From Cookies>)', () => {
    it('should return true if the request is authenticated', async () => {
      await setSessionCookie(req);

      const result = await monoCloud.isAuthenticated();

      expect(result).toBe(true);
    });

    it('should return false if the request is not authenticated', async () => {
      const result = await monoCloud.isAuthenticated();

      expect(result).toBe(false);
    });
  });

  describe('With Request and Response (req, res)', () => {
    it('should return true if the request is authenticated', async () => {
      await setSessionCookie(req);

      const res = new NextResponse();

      const result = await monoCloud.isAuthenticated(req, res);

      expect(result).toBe(true);
    });

    it('should return false if the request is not authenticated', async () => {
      const res = new NextResponse();

      const result = await monoCloud.isAuthenticated(req, res);

      expect(result).toBe(false);
    });
  });

  describe('With Request and Context (req, ctx)', () => {
    it('should return true if the request is authenticated', async () => {
      await setSessionCookie(req);

      const result = await monoCloud.isAuthenticated(req, { params: {} });

      expect(result).toBe(true);
    });

    it('should return false if the request is not authenticated', async () => {
      const result = await monoCloud.isAuthenticated(req, { params: {} });

      expect(result).toBe(false);
    });
  });
});
