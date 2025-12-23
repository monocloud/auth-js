import type {
  CookieOptions,
  MonoCloudResponse,
} from '@monocloud/auth-node-core';
import type { NextApiResponse } from 'next';
import { serialize } from 'cookie';

export default class MonoCloudPageRouterResponse implements MonoCloudResponse {
  constructor(public readonly res: NextApiResponse) {}

  setCookie(
    cookieName: string,
    value: string,
    options: CookieOptions
  ): Promise<void> {
    let cookies = this.res.getHeader('Set-Cookie') ?? [];

    /* v8 ignore if -- @preserve */
    if (!Array.isArray(cookies)) {
      cookies = [cookies as string];
    }

    this.res.setHeader('Set-Cookie', [
      ...cookies.filter(cookie => !cookie.startsWith(`${cookieName}=`)),
      serialize(cookieName, value, options),
    ]);

    return Promise.resolve();
  }

  /* v8 ignore next */
  redirect(url: string, statusCode?: number): void {
    this.res.redirect(statusCode ?? 302, url);
  }

  /* v8 ignore next */
  sendJson(data: any, statusCode?: number): void {
    this.res.status(statusCode ?? 200);
    this.res.json(data);
  }

  /* v8 ignore next */
  notFound(): void {
    this.res.status(404);
  }

  /* v8 ignore next */
  internalServerError(): void {
    this.res.status(500);
  }

  /* v8 ignore next */
  noContent(): void {
    this.res.status(204);
  }

  /* v8 ignore next */
  methodNotAllowed(): void {
    this.res.status(405);
  }

  /* v8 ignore next */
  setNoCache(): void {
    this.res.setHeader('Cache-Control', 'no-cache no-store');
    this.res.setHeader('Pragma', 'no-cache');
  }

  /* v8 ignore next */
  done(): any {
    this.res.end();
  }
}
