import type { MonoCloudRequest } from '@monocloud/auth-node-core';
import type { NextRequest } from 'next/server';
import { AppRouterContext } from '../types';

export default class MonoCloudAppRouterRequest implements MonoCloudRequest {
  constructor(
    public readonly req: NextRequest,
    public readonly ctx: AppRouterContext
  ) {}

  /* v8 ignore next */
  getRoute(parameter: string): string | string[] | undefined {
    return this.ctx.params?.[parameter];
  }

  getQuery(parameter: string): string | string[] | undefined {
    const url = new URL(this.req.url);
    return url.searchParams.get(parameter) ?? undefined;
  }

  getCookie(name: string): Promise<string | undefined> {
    return Promise.resolve(this.req.cookies.get(name)?.value);
  }

  async getRawRequest(): Promise<{
    method: string;
    url: string;
    body: Record<string, string> | string;
  }> {
    return {
      method: this.req.method,
      url: this.req.url,
      body: await this.req.text(),
    };
  }

  getAllCookies(): Promise<Map<string, string>> {
    const values = new Map<string, string>();
    this.req.cookies.getAll().forEach(x => {
      values.set(x.name, x.value);
    });
    return Promise.resolve(values);
  }
}
