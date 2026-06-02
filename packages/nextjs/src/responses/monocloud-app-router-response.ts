import type {
  CookieOptions,
  MonoCloudResponse,
} from '@monocloud/auth-node-core';
// eslint-disable-next-line import/extensions
import { NextResponse } from 'next/server.js';

export default class MonoCloudAppRouterResponse implements MonoCloudResponse {
  constructor(public res: NextResponse) {}

  setCookie(
    cookieName: string,
    value: string,
    options: CookieOptions
  ): Promise<void> {
    this.res.cookies.set(cookieName, value, options);
    return Promise.resolve();
  }

  redirect(url: string, statusCode: number | undefined = 307): void {
    const { headers } = this.res;
    this.res = NextResponse.redirect(url, { status: statusCode, headers });
  }

  sendJson(data: any, statusCode?: number): void {
    const { headers } = this.res;
    this.res = NextResponse.json(data, { status: statusCode, headers });
  }

  /* v8 ignore next */
  notFound(): void {
    const { headers } = this.res;
    this.res = new NextResponse(null, { status: 404, headers });
  }

  internalServerError(): void {
    const { headers } = this.res;
    this.res = new NextResponse(null, { status: 500, headers });
  }

  noContent(): void {
    const { headers } = this.res;
    this.res = new NextResponse(null, { status: 204, headers });
  }

  methodNotAllowed(): void {
    const { headers } = this.res;
    this.res = new NextResponse(null, { status: 405, headers });
  }

  setHeader(name: string, value: string): void {
    this.res.headers.set(name, value);
  }

  setNoCache(): void {
    this.res.headers.set(
      'Cache-Control',
      'private, no-cache, no-store, must-revalidate, max-age=0'
    );
    this.res.headers.set('Pragma', 'no-cache');
    this.res.headers.set('Expires', '0');
  }

  done(): any {
    return this.res;
  }
}
