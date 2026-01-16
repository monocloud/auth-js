/* eslint-disable import/no-extraneous-dependencies */
import { NextRequest, NextResponse } from 'next/server';
import { describe, it, expect } from 'vitest';
import {
  isAppRouter,
  getMonoCloudCookieReqRes,
  mergeResponse,
  getNextRequest,
  getNextResponse,
} from '../src/utils';
import MonoCloudAppRouterResponse from '../src/responses/monocloud-app-router-response';
import MonoCloudAppRouterRequest from '../src/requests/monocloud-app-router-request';
import MonoCloudPageRouterRequest from '../src/requests/monocloud-page-router-request';
import MonoCloudPageRouterResponse from '../src/responses/monocloud-page-router-response';
import { IncomingMessage, ServerResponse } from 'node:http';

describe('isAppRouter', () => {
  it('should return true for app router request', () => {
    const req = new NextRequest('http://example.com');
    expect(isAppRouter(req)).toBe(true);
  });

  it('should return false for other types of requests', () => {
    const req = {};
    expect(isAppRouter(req as unknown as NextRequest)).toBe(false);
  });
});

describe('getNextRequest', () => {
  const baseUrl = 'http://localhost:3000/api/auth';

  it('should return the exact same instance if input is already NextRequest', () => {
    const req = new NextRequest(baseUrl);
    const result = getNextRequest(req);
    expect(result).toBe(req);
  });

  it('should create a new NextRequest from a standard Request', () => {
    const req = new Request(baseUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: 'test' }),
    });

    const result = getNextRequest(req);

    expect(result).toBeInstanceOf(NextRequest);
    expect(result.url).toBe(baseUrl);
    expect(result.method).toBe('POST');
    expect(result.headers.get('content-type')).toBe('application/json');
  });
});

describe('getNextResponse', () => {
  it('should return the exact same instance if input is already NextResponse', () => {
    const res = new NextResponse('body');
    const result = getNextResponse(res);
    expect(result).toBe(res);
  });

  it('should convert a standard Response to NextResponse', async () => {
    const res = new Response('test payload', {
      status: 201,
      statusText: 'Created',
      headers: { 'X-Auth-Token': 'abc-123' },
    });

    const result = getNextResponse(res);

    expect(result).toBeInstanceOf(NextResponse);
    expect(result.status).toBe(201);
    expect(result.statusText).toBe('Created');
    expect(result.headers.get('X-Auth-Token')).toBe('abc-123');

    const text = await result.text();
    expect(text).toBe('test payload');
  });

  it('should return an empty NextResponse if input is not a Response object (fallback)', () => {
    const context = { params: { id: '1' } };

    const result = getNextResponse(context);

    expect(result).toBeInstanceOf(NextResponse);
    expect(result.status).toBe(200);
    expect(result.body).toBe(null);
  });

  it('should not crash if setting the URL fails (try/catch coverage)', () => {
    const res = new Response(null);
    Object.defineProperty(res, 'url', { value: 'http://foo.com' });

    const result = getNextResponse(res);

    expect(result).toBeInstanceOf(NextResponse);
  });
});

describe('getMonoCloudReqRes', () => {
  it('should return MonoCloudRequest and MonoCloudResponse for app router request', () => {
    const req = new NextRequest('http://example.com');
    const resOrCtx = new NextResponse();
    const { request, response } = getMonoCloudCookieReqRes(req, resOrCtx);
    expect(request).toBeInstanceOf(MonoCloudAppRouterRequest);
    expect(response).toBeInstanceOf(MonoCloudAppRouterResponse);
  });

  it('should return MonoCloudRequest and MonoCloudResponse for page router request', () => {
    const req = Object.create(IncomingMessage.prototype);
    const resOrCtx = Object.create(ServerResponse.prototype);

    const { request, response } = getMonoCloudCookieReqRes(req, resOrCtx);
    expect(request).toBeInstanceOf(MonoCloudPageRouterRequest);
    expect(response).toBeInstanceOf(MonoCloudPageRouterResponse);
  });
});

describe('mergeResponse', () => {
  it('should merge responses correctly', () => {
    const response1 = new NextResponse();
    response1.headers.set('header1', 'value1');
    response1.headers.set('location', 'shouldIgnore');
    response1.cookies.set('cookie1', 'value1');

    const response2 = new NextResponse();
    response2.headers.set('header2', 'value2');
    response2.headers.set('location', 'shouldKeep');
    response2.cookies.set('cookie2', 'value2');

    const mergedResponse = mergeResponse([response1, response2]);

    expect(mergedResponse.headers.get('header1')).toBe('value1');
    expect(mergedResponse.headers.get('header2')).toBe('value2');
    expect(mergedResponse.headers.get('location')).toBe('shouldKeep');

    expect(mergedResponse.cookies.get('cookie1')?.value).toBe('value1');
    expect(mergedResponse.cookies.get('cookie2')?.value).toBe('value2');
  });

  it('should handle empty array', () => {
    const mergedResponse = mergeResponse([]);
    expect(mergedResponse).toBeInstanceOf(NextResponse);
    expect(mergedResponse.cookies.getAll().length).toBe(0);

    let headerCount = 0;
    mergedResponse.headers.forEach(() => {
      headerCount += 1;
    });

    expect(headerCount).toBe(0);
  });
});
