/* eslint-disable @typescript-eslint/no-non-null-assertion */
// eslint-disable-next-line import/no-extraneous-dependencies
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { withDedupedLock, withLock } from '../src/lock';
import { MonoCloudJsError } from '../src/monocloud-js-error';
import { MonoCloudValidationError } from '@monocloud/auth-core';

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
    opts.requestImpl ?? ((_k: any, _o: any, cb: any): Promise<any> => cb())
  );

  Object.defineProperty(navigator, 'locks', {
    value: lm,
    configurable: true,
  });
};

const restoreLockEnvironment = (): void => {
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
};

describe('withLock()', () => {
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
    (globalThis.clearTimeout as any).mockRestore?.();

    restoreLockEnvironment();

    vi.restoreAllMocks();
  });

  it('web locks - does NOT wrap MonoCloudAuthBaseError (passes through)', async () => {
    setSecureContext(true);
    setWebLocksEnabled({
      enabled: true,
      requestImpl: (_key, _options, innerCb) => innerCb(),
    });

    const validationMsg = 'Ensure the user is authenticated';
    const cb = vi.fn(() => {
      throw new MonoCloudValidationError(validationMsg);
    });

    const p = withLock('k_validation', cb);
    await expect(p).rejects.not.toBeInstanceOf(MonoCloudJsError);
    await expect(p).rejects.toBeInstanceOf(MonoCloudValidationError);
    await expect(p).rejects.toThrow(validationMsg);
  });

  it('web locks - successfully acquires lock and returns callback result', async () => {
    setSecureContext(true);
    setWebLocksEnabled({ enabled: true });

    const cb = vi.fn(() => Promise.resolve('success_data'));
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

  it('web locks - wraps generic errors in MonoCloudJsError', async () => {
    setSecureContext(true);
    setWebLocksEnabled({ enabled: true });
    const genericError = new Error('Network request failed');
    const cb = vi.fn(() => {
      throw genericError;
    });
    const p = withLock('k_generic', cb);
    await expect(p).rejects.toBeInstanceOf(MonoCloudJsError);
    await expect(p).rejects.toThrow(
      'Failed to acquire lock: Network request failed'
    );
  });

  it('tabs lock - successfully acquires, runs, and releases lock', async () => {
    setSecureContext(false);
    setWebLocksEnabled({ enabled: true });

    tabLockMocks.acquireLock.mockResolvedValue(true);
    tabLockMocks.releaseLock.mockResolvedValue(undefined);

    const cb = vi.fn(() => Promise.resolve('fallback_data'));
    const result = await withLock('key_fallback', cb);

    expect(result).toBe('fallback_data');
    expect(tabLockMocks.acquireLock).toHaveBeenCalledWith('key_fallback', 5000);
    expect(cb).toHaveBeenCalled();
    expect(tabLockMocks.releaseLock).toHaveBeenCalledWith('key_fallback');
  });

  it('tabs lock - throws MonoCloudJsError if lock cannot be acquired', async () => {
    setSecureContext(false);
    setWebLocksEnabled({ enabled: true });

    tabLockMocks.acquireLock.mockResolvedValue(false);

    const cb = vi.fn();
    const p = withLock('key_busy', cb);

    await expect(p).rejects.toBeInstanceOf(MonoCloudJsError);
    await expect(p).rejects.toThrow('Failed to acquire lock.');
    expect(cb).not.toHaveBeenCalled();
  });

  it('tabs lock - releases lock even if callback crashes', async () => {
    setSecureContext(false);
    setWebLocksEnabled({ enabled: true });

    tabLockMocks.acquireLock.mockResolvedValue(true);
    const cb = vi.fn(() => {
      throw new Error('Business Logic Crash');
    });

    const p = withLock('key_crash', cb);

    await expect(p).rejects.toThrow('Business Logic Crash');
    expect(tabLockMocks.releaseLock).toHaveBeenCalledWith('key_crash');
  });

  it('web locks - triggers the abort signal when the 5000ms timeout is reached', () => {
    setSecureContext(true);

    let capturedSignal: AbortSignal;

    setWebLocksEnabled({
      enabled: true,
      requestImpl: (_k, options, _cb) => {
        capturedSignal = options.signal;
        return new Promise(() => {});
      },
    });

    const cb = vi.fn();

    withLock('k_timer', cb).catch(() => {});
    vi.advanceTimersByTime(5000);
    expect(capturedSignal!.aborted).toBe(true);
  });

  it('tabs lock - releases lock immediately when pagehide event fires', async () => {
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
        expect.any(Function),
        expect.objectContaining({ once: true })
      );
    });

    window.dispatchEvent(new Event('pagehide'));

    expect(tabLockMocks.releaseLock).toHaveBeenCalledWith('k_pagehide_test');

    finishCallback!();
    await promise;
  });
});

describe('withDedupedLock()', () => {
  beforeEach(() => {
    setSecureContext(true);
    setWebLocksEnabled({ enabled: true });
  });

  afterEach(restoreLockEnvironment);

  it('collapses concurrent calls with the same key into one execution', async () => {
    const cb = vi.fn(() => Promise.resolve('value'));

    const [a, b, c] = await Promise.all([
      withDedupedLock('k_dedupe', 'lock_k', cb),
      withDedupedLock('k_dedupe', 'lock_k', cb),
      withDedupedLock('k_dedupe', 'lock_k', cb),
    ]);

    expect(cb).toHaveBeenCalledTimes(1);
    expect(a).toBe('value');
    expect(b).toBe('value');
    expect(c).toBe('value');
  });

  it('runs separate executions for distinct keys', async () => {
    const cb = vi.fn((value: string) => Promise.resolve(value));

    const [a, b] = await Promise.all([
      withDedupedLock('k_a', 'lock_k', () => cb('a')),
      withDedupedLock('k_b', 'lock_k', () => cb('b')),
    ]);

    expect(cb).toHaveBeenCalledTimes(2);
    expect(a).toBe('a');
    expect(b).toBe('b');
  });

  it('releases the key after resolution so subsequent calls re-run', async () => {
    const cb = vi.fn(() => Promise.resolve('value'));

    await withDedupedLock('k_release', 'lock_k', cb);
    await withDedupedLock('k_release', 'lock_k', cb);

    expect(cb).toHaveBeenCalledTimes(2);
  });

  it('propagates rejection to all joined callers and releases the key', async () => {
    const error = new MonoCloudValidationError('boom');
    const cb = vi.fn(() => Promise.reject(error));

    const a = withDedupedLock('k_reject', 'lock_k', cb);
    const b = withDedupedLock('k_reject', 'lock_k', cb);

    await expect(a).rejects.toBe(error);
    await expect(b).rejects.toBe(error);
    expect(cb).toHaveBeenCalledTimes(1);

    const cb2 = vi.fn(() => Promise.resolve('ok'));
    await expect(withDedupedLock('k_reject', 'lock_k', cb2)).resolves.toBe(
      'ok'
    );
    expect(cb2).toHaveBeenCalledTimes(1);
  });
});
