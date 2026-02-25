import { IStorage } from './types';

/**
 * In-memory implementation of {@link IStorage}.
 *
 * Useful for testing or for sessions that should not persist across page reloads.
 *
 * @category Classes
 */
export class MemoryStorage implements IStorage {
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

/**
 * `window.localStorage`-backed implementation of {@link IStorage}.
 *
 * This is the default storage used by `MonoCloudJSCoreClient`.
 *
 * @category Classes
 */
export class LocalStorage implements IStorage {
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

/**
 * `window.sessionStorage`-backed implementation of {@link IStorage}.
 *
 * Data persists for the lifetime of the current browser tab.
 *
 * @category Classes
 */
export class SessionStorage implements IStorage {
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
