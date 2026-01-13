import TabLock from 'browser-tabs-lock';
import { MonoCloudJsError } from './monocloud-js-error';

const tabLock = new TabLock();

export async function withLock<T = any>(
  key: string,
  cb: () => Promise<T>
): Promise<T> {
  const releaseLocks = async (): Promise<void> => {
    await tabLock.releaseLock(key);
    window.removeEventListener('pagehide', releaseLocks);
  };

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
    } catch (error) {
      throw new MonoCloudJsError(
        `Failed to acquire lock : ${(error as Error).message}`
      );
    }
  } else {
    const acquired = await tabLock.acquireLock(key, 5000);
    if (!acquired) {
      throw new MonoCloudJsError('Failed to acquire lock.');
    }

    try {
      window.addEventListener('pagehide', releaseLocks);
      return await cb();
    } finally {
      await tabLock.releaseLock(key);
    }
  }
}
