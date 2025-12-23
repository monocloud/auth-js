/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type { MonoCloudRequest } from '@monocloud/auth-node-core';
import type { NextApiRequest } from 'next';

export default class MonoCloudPageRouterRequest implements MonoCloudRequest {
  constructor(public readonly req: NextApiRequest) {}

  /* v8 ignore next */
  getRoute(parameter: string): string | string[] | undefined {
    return this.req.query[parameter];
  }

  /* v8 ignore next */
  getQuery(parameter: string): string | string[] | undefined {
    return this.req.query[parameter];
  }

  /* v8 ignore next */
  getCookie(name: string): Promise<string | undefined> {
    return Promise.resolve(this.req.cookies[name]);
  }

  /* v8 ignore next */
  getRawRequest(): Promise<{
    method: string;
    url: string;
    body: Record<string, string> | string;
  }> {
    return Promise.resolve({
      method: this.req.method!,
      url: this.req.url!,
      body: this.req.body,
    });
  }

  getAllCookies(): Promise<Map<string, string>> {
    const values = new Map<string, string>();
    const { cookies } = this.req;
    Object.keys(cookies).forEach(x => {
      const val = cookies[x];
      /* v8 ignore else -- @preserve */
      if (typeof x === 'string' && typeof val === 'string') {
        values.set(x, val);
      }
    });
    return Promise.resolve(values);
  }
}
