// eslint-disable-next-line import/no-extraneous-dependencies
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { withLock } from '../src/lock';
import { MonoCloudJsError } from '../src/monocloud-js-error';
import {
  MonoCloudAuthBaseError,
  MonoCloudValidationError,
} from '@monocloud/auth-core';

const tabLockMocks = vi.hoisted(() => ({
  acquireLock: vi.fn(),

  releaseLock: vi.fn(),
}));

vi.mock('browser-tabs-lock', () => {
  return {
    default: class {
      acquireLock = tabLockMocks.acquireLock;

      releaseLock = tabLockMocks.releaseLock;
    },
  };
});

describe('withLock()', () => {
  const originalLockManager = (globalThis as any).LockManager;
  const originalLocks = (navigator as any).locks;
  const originalSecureContext = (window as any).isSecureContext;

  const setSecureContext = (val: boolean): void => {
    Object.defineProperty(window, 'isSecureContext', {
      value: val,
      configurable: true,
    });
  };

  const setWebLocksEnabled = (opts: {
    enabled: boolean;
    requestImpl?: (key: string, options: any, cb: () => any) => any;
  }): void => {
    class TestLockManager {}
    (globalThis as any).LockManager = TestLockManager;

    if (!opts.enabled) {
      Object.defineProperty(navigator, 'locks', {
        value: {},
        configurable: true,
      });
      return;
    }

    const lm = new TestLockManager() as any;
    lm.request = vi.fn(
      opts.requestImpl ??
        (async (_k: any, _o: any, cb: any): Promise<any> => cb())
    );

    Object.defineProperty(navigator, 'locks', {
      value: lm,
      configurable: true,
    });
  };

  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(window, 'addEventListener');
    vi.spyOn(window, 'removeEventListener');
    vi.spyOn(globalThis, 'clearTimeout');

    tabLockMocks.acquireLock.mockReset();
    tabLockMocks.releaseLock.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
    (window.addEventListener as any).mockRestore?.();
    (window.removeEventListener as any).mockRestore?.();

    if (originalLockManager) {
      (globalThis as any).LockManager = originalLockManager;
    } else {
      delete (globalThis as any).LockManager;
    }

    Object.defineProperty(navigator, 'locks', {
      value: originalLocks,
      configurable: true,
    });
    Object.defineProperty(window, 'isSecureContext', {
      value: originalSecureContext,
      configurable: true,
    });

    vi.restoreAllMocks();
  });

  it('does NOT wrap MonoCloudAuthBaseError (passes through)', async () => {
    setSecureContext(true);
    setWebLocksEnabled({
      enabled: true,
      requestImpl: async (_key, _options, innerCb) => innerCb(),
    });

    const validationMsg = 'Ensure the user is authenticated';
    const cb = vi.fn(async () => {
      throw new MonoCloudValidationError(validationMsg);
    });

    const p = withLock('k_validation', cb);
    await expect(p).rejects.not.toBeInstanceOf(MonoCloudJsError);
    await expect(p).rejects.toBeInstanceOf(MonoCloudValidationError);
    await expect(p).rejects.toThrow(validationMsg);
  });

  it('successfully acquires lock and returns callback result', async () => {
    setSecureContext(true);
    setWebLocksEnabled({ enabled: true });

    const cb = vi.fn(async () => 'success_data');
    const result = await withLock('key1', cb);

    expect(result).toBe('success_data');
    expect(cb).toHaveBeenCalled();
    const lm = (navigator as any).locks;
    expect(lm.request).toHaveBeenCalledWith(
      'key1',
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
      expect.any(Function)
    );
  });

  it('passes through MonoCloudAuthBaseError without wrapping', async () => {
    setSecureContext(true);
    setWebLocksEnabled({ enabled: true });

    const validationMsg = 'Ensure the user is authenticated';
    const cb = vi.fn(async () => {
      throw new MonoCloudValidationError(validationMsg);
    });

    const p = withLock('k_validation', cb);
    await expect(p).rejects.toThrow(MonoCloudValidationError);
    await expect(p).rejects.toBeInstanceOf(MonoCloudAuthBaseError);
  });

  it('wraps generic errors in MonoCloudJsError', async () => {
    setSecureContext(true);
    setWebLocksEnabled({ enabled: true });
    const genericError = new Error('Network request failed');
    const cb = vi.fn(async () => {
      throw genericError;
    });
    const p = withLock('k_generic', cb);
    await expect(p).rejects.toBeInstanceOf(MonoCloudJsError);
    await expect(p).rejects.toThrow(
      'Failed to acquire lock : Network request failed'
    );
  });

  it('handles Lock Timeout with specific message', async () => {
    setSecureContext(true);
    setWebLocksEnabled({
      enabled: true,
      requestImpl: async () => {
        const err = new Error('The operation was aborted');
        err.name = 'AbortError';
        throw err;
      },
    });

    const cb = vi.fn();
    const p = withLock('k_timeout', cb);
    await expect(p).rejects.toBeInstanceOf(MonoCloudJsError);
    await expect(p).rejects.toThrow(
      'Failed to acquire lock: Timed out after 5000ms'
    );
  });

  it('successfully acquires, runs, and releases lock', async () => {
    setSecureContext(false);
    setWebLocksEnabled({ enabled: true });

    tabLockMocks.acquireLock.mockResolvedValue(true);
    tabLockMocks.releaseLock.mockResolvedValue(undefined);

    const cb = vi.fn(async () => 'fallback_data');
    const result = await withLock('key_fallback', cb);

    expect(result).toBe('fallback_data');
    expect(tabLockMocks.acquireLock).toHaveBeenCalledWith('key_fallback', 5000);
    expect(cb).toHaveBeenCalled();
    expect(tabLockMocks.releaseLock).toHaveBeenCalledWith('key_fallback');
    expect(window.removeEventListener).toHaveBeenCalledWith(
      'pagehide',
      expect.any(Function)
    );
  });

  it('throws MonoCloudJsError if lock cannot be acquired', async () => {
    setSecureContext(false);
    setWebLocksEnabled({ enabled: true });

    tabLockMocks.acquireLock.mockResolvedValue(false);

    const cb = vi.fn();
    const p = withLock('key_busy', cb);

    await expect(p).rejects.toBeInstanceOf(MonoCloudJsError);
    await expect(p).rejects.toThrow('Failed to acquire lock.');
    expect(cb).not.toHaveBeenCalled();
  });

  it('releases lock even if callback crashes', async () => {
    setSecureContext(false);
    setWebLocksEnabled({ enabled: true });

    tabLockMocks.acquireLock.mockResolvedValue(true);
    const cb = vi.fn(async () => {
      throw new Error('Business Logic Crash');
    });

    const p = withLock('key_crash', cb);

    await expect(p).rejects.toThrow('Business Logic Crash');
    expect(tabLockMocks.releaseLock).toHaveBeenCalledWith('key_crash');
    expect(window.removeEventListener).toHaveBeenCalled();
  });

  it('triggers the abort signal when the 5000ms timeout is reached', async () => {
    setSecureContext(true);

    let capturedSignal: AbortSignal;

    setWebLocksEnabled({
      enabled: true,
      requestImpl: async (_k, options, _cb) => {
        capturedSignal = options.signal;
        return new Promise(() => {});
      },
    });

    const cb = vi.fn();

    withLock('k_timer', cb).catch(() => {});
    vi.advanceTimersByTime(5000);
    expect(capturedSignal!.aborted).toBe(true);
  });

  it('releases lock immediately when pagehide event fires', async () => {
    setSecureContext(false);
    setWebLocksEnabled({ enabled: true });

    tabLockMocks.acquireLock.mockResolvedValue(true);

    let finishCallback: () => void;
    const cb = vi.fn(
      () =>
        new Promise<void>(resolve => {
          finishCallback = resolve;
        })
    );

    const promise = withLock('k_pagehide_test', cb);
    await vi.waitFor(() => {
      expect(window.addEventListener).toHaveBeenCalledWith(
        'pagehide',
        expect.any(Function)
      );
    });

    window.dispatchEvent(new Event('pagehide'));

    expect(tabLockMocks.releaseLock).toHaveBeenCalledWith('k_pagehide_test');

    finishCallback!();
    await promise;
  });
});
