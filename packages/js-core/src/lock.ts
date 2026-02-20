import TabLock from 'browser-tabs-lock';
import { MonoCloudJsError } from './monocloud-js-error';
import { MonoCloudAuthBaseError } from '@monocloud/auth-core';

const tabLock = new TabLock();

export async function withLock<T = any>(
  key: string,
  cb: () => Promise<T>
): Promise<T> {
  if (navigator.locks instanceof LockManager && window.isSecureContext) {
    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), 5000);
    try {
      return await navigator.locks.request(
        key,
        { signal: abortController.signal },
        async () => {
          clearTimeout(timeout);
          return await cb();
        }
      );
    } catch (error: any) {
      if (error instanceof MonoCloudAuthBaseError) {
        throw error;
      }

      throw new MonoCloudJsError(`Failed to acquire lock : ${error.message}`);
    }
  } else {
    const acquired = await tabLock.acquireLock(key, 5000);
    if (!acquired) {
      throw new MonoCloudJsError('Failed to acquire lock.');
    }

    const onPageHide = async (): Promise<void> => {
      await tabLock.releaseLock(key);
      window.removeEventListener('pagehide', onPageHide);
    };

    try {
      window.addEventListener('pagehide', onPageHide);
      return await cb();
    } finally {
      await tabLock.releaseLock(key);
    }
  }
}
