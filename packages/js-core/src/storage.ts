import { IStorage } from './types';

class MemoryStorage implements IStorage {
  private store: Record<string, string> = {};

  getItem(key: string): Promise<string | null> {
    return Promise.resolve(this.store[key] ?? null);
  }

  removeItem(key: string): Promise<void> {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete this.store[key];
    return Promise.resolve();
  }

  setItem(key: string, value: string): Promise<void> {
    this.store[key] = value;
    return Promise.resolve();
  }
}

class LocalStorage implements IStorage {
  getItem(key: string): Promise<string | null> {
    return Promise.resolve(window.localStorage.getItem(key));
  }

  removeItem(key: string): Promise<void> {
    window.localStorage.removeItem(key);
    return Promise.resolve();
  }

  setItem(key: string, value: string): Promise<void> {
    window.localStorage.setItem(key, value);
    return Promise.resolve();
  }
}

class SessionStorage implements IStorage {
  getItem(key: string): Promise<string | null> {
    return Promise.resolve(window.sessionStorage.getItem(key));
  }

  removeItem(key: string): Promise<void> {
    window.sessionStorage.removeItem(key);
    return Promise.resolve();
  }

  setItem(key: string, value: string): Promise<void> {
    window.sessionStorage.setItem(key, value);
    return Promise.resolve();
  }
}

/**
 * In memory storage for `MonoCloudJsClient`
 *
 * @example
 *
 * const monoCloudClient = new MonoCloudJsClient(options, memoryStorage());
 */
export const memoryStorage = (): IStorage => new MemoryStorage();

/**
 * LocalStorage for `MonoCloudJsClient`. This is the default storage.
 * Same as `window.localStorage`.
 *
 * @example
 *
 * const monoCloudClient = new MonoCloudJsClient(options, localStorage());
 */
export const localStorage = (): IStorage => new LocalStorage();

/**
 * SessionStorage for `MonoCloudJsClient`. Same as `window.sessionStorage`.
 *
 * @example
 *
 * const monoCloudClient = new MonoCloudJsClient(options, sessionStorage());
 */
export const sessionStorage = (): IStorage => new SessionStorage();
