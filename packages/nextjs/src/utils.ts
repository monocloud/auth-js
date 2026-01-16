// eslint-disable-next-line import/extensions
import { NextRequest, NextResponse } from 'next/server.js';
import type { NextApiRequest, NextApiResponse } from 'next/types';
import {
  MonoCloudValidationError,
  type IMonoCloudCookieRequest,
  type IMonoCloudCookieResponse,
} from '@monocloud/auth-node-core';
import { AppRouterContext } from './types';
import MonoCloudAppRouterRequest from './requests/monocloud-app-router-request';
import MonoCloudPageRouterRequest from './requests/monocloud-page-router-request';
import MonoCloudAppRouterResponse from './responses/monocloud-app-router-response';
import MonoCloudPageRouterResponse from './responses/monocloud-page-router-response';
import MonoCloudCookieResponse from './responses/monocloud-cookie-response';
import MonoCloudCookieRequest from './requests/monocloud-cookie-request';
import { IncomingMessage, ServerResponse } from 'node:http';
import { isPresent } from '@monocloud/auth-node-core/internal';

export const isMonoCloudRequest = (
  req: unknown
): req is IMonoCloudCookieRequest =>
  req instanceof MonoCloudAppRouterRequest ||
  req instanceof MonoCloudPageRouterRequest ||
  req instanceof MonoCloudCookieRequest;

export const isMonoCloudResponse = (
  res: unknown
): res is IMonoCloudCookieResponse =>
  res instanceof MonoCloudAppRouterResponse ||
  res instanceof MonoCloudPageRouterResponse ||
  res instanceof MonoCloudCookieResponse;

export const isAppRouter = (req: unknown): boolean =>
  req instanceof Request ||
  (req as Request).headers instanceof Headers ||
  typeof (req as Request).bodyUsed === 'boolean';

export const getNextRequest = (req: Request | NextRequest): NextRequest => {
  if (req instanceof NextRequest) {
    return req;
  }

  return new NextRequest(req.url, {
    method: req.method,
    headers: req.headers,
    body: req.body,
    /* v8 ignore next -- @preserve */
    duplex: (req as any).duplex ?? 'half',
  });
};

export const getNextResponse = (
  res: Response | NextResponse | AppRouterContext
): NextResponse => {
  if (res instanceof NextResponse) {
    return res;
  }

  if (res instanceof Response) {
    const nextResponse = new NextResponse(res.body, {
      status: res.status,
      statusText: res.statusText,
      headers: res.headers,
      url: res.url,
    });

    try {
      /* v8 ignore else -- @preserve */
      if (!isPresent(nextResponse.url)) {
        (nextResponse as any).url = res.url;
      }
    } catch {
      // ignore
    }

    return nextResponse;
  }

  return new NextResponse();
};

export const getMonoCloudCookieReqRes = (
  req: unknown,
  resOrCtx: unknown
): {
  request: IMonoCloudCookieRequest;
  response: IMonoCloudCookieResponse;
} => {
  let request: IMonoCloudCookieRequest;
  let response: IMonoCloudCookieResponse;

  if (isAppRouter(req)) {
    request = new MonoCloudAppRouterRequest(getNextRequest(req as Request));

    response =
      resOrCtx instanceof Response
        ? new MonoCloudAppRouterResponse(getNextResponse(resOrCtx))
        : new MonoCloudCookieResponse();
  } else {
    if (
      !(req instanceof IncomingMessage) ||
      !(resOrCtx instanceof ServerResponse)
    ) {
      throw new MonoCloudValidationError(
        'Invalid pages router request and response'
      );
    }
    request = new MonoCloudPageRouterRequest(req as NextApiRequest);
    response = new MonoCloudPageRouterResponse(resOrCtx as NextApiResponse);
  }

  return { request, response };
};

export const mergeResponse = (responses: NextResponse[]): NextResponse => {
  const resp = responses.pop();

  if (!resp) {
    return new NextResponse();
  }

  responses.forEach(response => {
    response.headers.forEach((v, k) => {
      if ((k === 'location' && !resp.headers.has(k)) || k !== 'location') {
        resp.headers.set(k, v);
      }
    });

    response.cookies.getAll().forEach(c => {
      const { name, value, ...cookieOpt } = c;
      resp.cookies.set(name, value, cookieOpt);
    });
  });

  return resp;
};
