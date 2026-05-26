import TabLock from 'browser-tabs-lock';
import { MonoCloudJsError } from './monocloud-js-error';
import { MonoCloudAuthBaseError } from '@monocloud/auth-core';

const tabLock = new TabLock();
const LOCK_TIMEOUT_MS = 5000;

const inFlight = new Map<string, Promise<unknown>>();

export function withDedupedLock<T = unknown>(
  dedupeKey: string,
  lockKey: string,
  cb: () => Promise<T>
): Promise<T> {
  const existing = inFlight.get(dedupeKey) as Promise<T> | undefined;
  if (existing) {
    return existing;
  }

  const promise = withLock(lockKey, cb).finally(() => {
    /* v8 ignore else -- @preserve */
    if (inFlight.get(dedupeKey) === promise) {
      inFlight.delete(dedupeKey);
    }
  });

  inFlight.set(dedupeKey, promise);
  return promise;
}

export async function withLock<T = unknown>(
  key: string,
  cb: () => Promise<T>
): Promise<T> {
  if (navigator.locks !== undefined && window.isSecureContext) {
    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), LOCK_TIMEOUT_MS);
    try {
      return await navigator.locks.request(
        key,
        { signal: abortController.signal },
        // eslint-disable-next-line require-await
        async () => cb()
      );
    } catch (error) {
      if (error instanceof MonoCloudAuthBaseError) {
        throw error;
      }

      throw new MonoCloudJsError(
        `Failed to acquire lock: ${(error as Error).message}`
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  const acquired = await tabLock.acquireLock(key, LOCK_TIMEOUT_MS);
  if (!acquired) {
    throw new MonoCloudJsError('Failed to acquire lock.');
  }

  const onPageHide = async (): Promise<void> => {
    await tabLock.releaseLock(key);
  };

  window.addEventListener('pagehide', onPageHide, { once: true });

  try {
    return await cb();
  } finally {
    window.removeEventListener('pagehide', onPageHide);
    await tabLock.releaseLock(key);
  }
}
