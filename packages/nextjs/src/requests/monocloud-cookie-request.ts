import type { IMonoCloudCookieRequest } from '@monocloud/auth-node-core';

export default class MonoCloudCookieRequest implements IMonoCloudCookieRequest {
  /* v8 ignore next */
  async getCookie(name: string): Promise<string | undefined> {
    // @ts-expect-error Cannot find module 'next/headers'
    const { cookies } = await import('next/headers');

    return (await cookies()).get(name)?.value;
  }

  async getAllCookies(): Promise<Map<string, string>> {
    const values = new Map<string, string>();
    // @ts-expect-error Cannot find module 'next/headers'
    const { cookies } = await import('next/headers');

    (await cookies()).getAll().forEach((x: any) => {
      values.set(x.name, x.value);
    });
    return values;
  }
}
