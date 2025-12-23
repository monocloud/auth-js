/* eslint-disable import/no-extraneous-dependencies */
import { NextRequest, NextResponse } from 'next/server';
import { describe, it, expect } from 'vitest';
import { isAppRouter, getMonoCloudReqRes, mergeResponse } from '../src/utils';
import MonoCloudAppRouterResponse from '../src/responses/monocloud-app-router-response';
import MonoCloudAppRouterRequest from '../src/requests/monocloud-app-router-request';
import { NextAnyRequest, NextAnyResponse } from '../src/types';
import MonoCloudPageRouterRequest from '../src/requests/monocloud-page-router-request';
import MonoCloudPageRouterResponse from '../src/responses/monocloud-page-router-response';

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

describe('getMonoCloudReqRes', () => {
  it('should return MonoCloudRequest and MonoCloudResponse for app router request', () => {
    const req = new NextRequest('http://example.com');
    const resOrCtx = new NextResponse();
    const { request, response } = getMonoCloudReqRes(req, resOrCtx);
    expect(request).toBeInstanceOf(MonoCloudAppRouterRequest);
    expect(response).toBeInstanceOf(MonoCloudAppRouterResponse);
  });

  it('should return MonoCloudRequest and MonoCloudResponse for page router request', () => {
    const req = {};
    const resOrCtx = {};
    const { request, response } = getMonoCloudReqRes(
      req as unknown as NextAnyRequest,
      resOrCtx as unknown as NextAnyResponse
    );
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
