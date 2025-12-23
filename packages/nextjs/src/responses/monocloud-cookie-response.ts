/* eslint-disable no-console */
import type {
  CookieOptions,
  IMonoCloudCookieResponse,
} from '@monocloud/auth-node-core';

let isWarned = false;

export default class MonoCloudCookieResponse implements IMonoCloudCookieResponse {
  async setCookie(
    cookieName: string,
    value: string,
    options: CookieOptions
  ): Promise<void> {
    try {
      // @ts-expect-error Cannot find module 'next/headers'
      const { cookies } = await import('next/headers');

      (await cookies()).set(cookieName, value, options);
    } catch (e: any) {
      if (!isWarned) {
        console.warn(e.message);
        isWarned = true;
      }
    }
  }
}
