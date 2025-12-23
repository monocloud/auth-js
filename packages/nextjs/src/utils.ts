import { NextResponse, type NextRequest } from 'next/server';
import type { NextApiRequest, NextApiResponse } from 'next/types';
import type {
  MonoCloudRequest,
  MonoCloudResponse,
} from '@monocloud/auth-node-core';
import { AppRouterContext, NextAnyRequest, NextAnyResponse } from './types';
import MonoCloudAppRouterRequest from './requests/monocloud-app-router-request';
import MonoCloudPageRouterRequest from './requests/monocloud-page-router-request';
import MonoCloudAppRouterResponse from './responses/monocloud-app-router-response';
import MonoCloudPageRouterResponse from './responses/monocloud-page-router-response';

export const isAppRouter = (req: NextAnyRequest): boolean =>
  req instanceof Request ||
  req.headers instanceof Headers ||
  typeof (req as unknown as Request).bodyUsed === 'boolean';

export const getMonoCloudReqRes = (
  req: NextAnyRequest,
  resOrCtx: NextAnyResponse
): {
  request: MonoCloudRequest;
  response: MonoCloudResponse;
} => {
  let request: MonoCloudRequest;
  let response: MonoCloudResponse;

  if (isAppRouter(req)) {
    const ctx: AppRouterContext =
      resOrCtx instanceof NextResponse
        ? { params: {} }
        : (resOrCtx as AppRouterContext);

    request = new MonoCloudAppRouterRequest(req as NextRequest, ctx);

    const res =
      resOrCtx instanceof NextResponse ? resOrCtx : new NextResponse();

    response = new MonoCloudAppRouterResponse(res);
  } else {
    /* c8 ignore start */
    request = new MonoCloudPageRouterRequest(req as NextApiRequest);
    response = new MonoCloudPageRouterResponse(resOrCtx as NextApiResponse);
    /* c8 ignore stop */
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
