/* eslint-disable import/no-extraneous-dependencies */
import { NextRequest, NextResponse } from 'next/server';
import { beforeEach, it, describe, expect, vi } from 'vitest';
import { MonoCloudNextClient } from '../../../src';
import {
  defaultDiscovery,
  noTokenAndUserInfo,
  setupOp,
} from '../../op-helpers.js';
import {
  defaultSessionCookieValue,
  setSessionCookie,
} from '../../common-helper';

let req: NextRequest;

vi.mock('next/headers', () => {
  return {
    cookies: (): any => ({
      get: (name: string) => req.cookies.get(name),
      getAll: () => req.cookies.getAll(),
    }),
  };
});

describe('MonoCloud.getSession() - App Router', () => {
  let monoCloud: MonoCloudNextClient;
  beforeEach(() => {
    setupOp(defaultDiscovery, noTokenAndUserInfo);

    req = new NextRequest('http://localhost:3000/');

    monoCloud = new MonoCloudNextClient();
  });

  it('should return undefined if there is no session (Request, Response)', async () => {
    const nextRes = new Response();

    const session = await monoCloud.getSession(
      new Request('http://localhost:3000/'),
      nextRes
    );

    expect(session).toBeUndefined();
  });

  it('should return undefined if there is no session (NextRequest, NextResponse)', async () => {
    const nextRes = new NextResponse();

    const session = await monoCloud.getSession(req, nextRes);

    expect(session).toBeUndefined();
  });

  it('should return the session of the current user (NextRequest, NextResponse)', async () => {
    await setSessionCookie(req);

    const nextRes = new NextResponse();

    const session = await monoCloud.getSession(req, nextRes);

    expect(session).toEqual(defaultSessionCookieValue);
  });

  it('should return undefined if there is no session (NextRequest)', async () => {
    const session = await monoCloud.getSession(req);

    expect(session).toBeUndefined();
  });

  it('should return the session of the current user (NextRequest)', async () => {
    await setSessionCookie(req);

    const session = await monoCloud.getSession(req);

    expect(session).toEqual(defaultSessionCookieValue);
  });

  it('should return undefined if there is no session (<From Cookies>)', async () => {
    const session = await monoCloud.getSession();

    expect(session).toBeUndefined();
  });

  it('should return the session of the current user (<From Cookies>)', async () => {
    await setSessionCookie(req);

    const session = await monoCloud.getSession();

    expect(session).toEqual(defaultSessionCookieValue);
  });
});
