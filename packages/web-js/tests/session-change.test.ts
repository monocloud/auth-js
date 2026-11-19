// eslint-disable-next-line import/no-extraneous-dependencies
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  fetchBuilder,
  generateIdToken,
  MockWindow,
} from '@monocloud/auth-test-utils';
import type { MonoCloudSession } from '@monocloud/auth-core';
import { now } from '@monocloud/auth-core/internal';
import type {
  CallbackState,
  MonoCloudWebJSClient,
  MonoCloudWebJSClientOptions,
} from '../src';
import {
  ensureLockManagerStub,
  sessionKey,
  setSession,
  testInstance,
  VanillaJsMockStorage,
} from './utils';

const tabLockMocks = vi.hoisted(() => ({
  acquireLock: vi.fn(() => true),
  releaseLock: vi.fn(() => void 0),
}));

vi.mock('browser-tabs-lock', () => {
  return {
    default: class TabLockMock {
      acquireLock = tabLockMocks.acquireLock;

      releaseLock = tabLockMocks.releaseLock;
    },
  };
});

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
}

const deferred = <T = void>(): Deferred<T> => {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

const flush = (): Promise<void> =>
  new Promise(resolve => {
    setTimeout(resolve, 0);
  });

class HeldReadStorage extends VanillaJsMockStorage {
  private heldRead?: Promise<void>;

  holdNextRead(): () => void {
    const gate = deferred();
    this.heldRead = gate.promise;
    return () => gate.resolve();
  }

  getItem(key: string): Promise<string | null> {
    const value = super.getItem(key);
    const held = this.heldRead;
    this.heldRead = undefined;
    return held ? held.then(() => value) : value;
  }
}

const storedSession = (): MonoCloudSession => ({
  user: { sub: 'sub' },
  accessTokens: [
    {
      accessToken: 'at',
      scopes: 'openid',
      requestedScopes: 'openid',
      accessTokenExpiration: now() + 1000,
    },
  ],
  authorizedScopes: 'openid',
  refreshToken: 'rt',
});

const refreshResponse = (
  refreshToken: string,
  next: string
): Parameters<ReturnType<typeof fetchBuilder>['configureRefreshToken']>[0] => ({
  body: `grant_type=refresh_token&refresh_token=${refreshToken}`,
  accessToken: `at-${next}`,
  refreshToken: `rt-${next}`,
  scope: 'openid',
  skipIdToken: true,
});

const sessions = (listener: ReturnType<typeof vi.fn>): unknown[] =>
  listener.mock.calls.map(([session]) => session);

describe('onSessionChange()', () => {
  let mockWindow: MockWindow;
  let mockStorage: HeldReadStorage;

  const signInCallbackClient = (
    options: Partial<MonoCloudWebJSClientOptions> = {}
  ): MonoCloudWebJSClient => {
    mockWindow
      .setHash('#state=state&access_token=new-at&expires_in=600&scope=openid')
      .setPathname('/callback')
      .assert();

    const state: CallbackState = {
      state: 'state',
      mode: 'redirect',
      scopes: 'openid',
      responseType: 'token',
    };

    mockStorage.setCallbackState(state);

    return testInstance({
      storage: mockStorage,
      fetchUserinfo: false,
      postCallback: vi.fn(),
      ...options,
    });
  };

  beforeEach(() => {
    mockWindow = new MockWindow();
    mockStorage = new HeldReadStorage();
    ensureLockManagerStub();
  });

  afterEach(() => {
    mockWindow.restore();
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  describe('session writes', () => {
    it('notifies every write with the value written, in write order', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureRefreshToken(refreshResponse('rt', '1'))
        .configureUserinfo({
          accessToken: 'at-1',
          claims: { sub: 'sub', name: 'Updated' },
        })
        .configureRefreshToken(refreshResponse('rt-1', '2'))
        .createSpy();

      await setSession(mockStorage, storedSession());

      const instance = testInstance({
        storage: mockStorage,
        fetchUserinfo: false,
      });

      const listener = vi.fn();
      instance.onSessionChange(listener);
      await vi.waitFor(() => expect(listener).toHaveBeenCalledTimes(1));

      const expected = [await instance.getSession()];

      await instance.refreshSession();
      expected.push(await instance.getSession());

      await instance.refetchUserInfo();
      expected.push(await instance.getSession());

      await instance.getTokens({ forceRefresh: true });
      expected.push(await instance.getSession());

      await instance.signOut({ federatedSignOut: false });
      expected.push(undefined);

      expect(sessions(listener)).toEqual(expected);
      expect(expected[3]?.refreshToken).toBe('rt-2');
      expect(expected[2]?.user).toEqual({ sub: 'sub', name: 'Updated' });
      fetchSpy.assert();
    });

    it('notifies the session written by a popup sign-in before postCallback runs', async () => {
      const idToken = await generateIdToken();

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureTokenEndpoint({ accessToken: 'popup-at', idToken })
        .createSpy();

      mockWindow.assert();

      const mockPopup = {
        close: vi.fn(),
        closed: false,
        location: { href: '' },
      } as unknown as Window;

      vi.spyOn(window, 'open').mockReturnValue(mockPopup);

      const postCallback = vi.fn();

      const instance = testInstance({
        storage: mockStorage,
        validateIdToken: false,
        fetchUserinfo: false,
        postCallback,
      });

      const listener = vi.fn();
      instance.onSessionChange(listener);
      await vi.waitFor(() => expect(listener).toHaveBeenCalledWith(undefined));

      const signIn = instance.signIn({ mode: 'popup' });

      await vi.waitFor(() => expect(mockPopup.location.href).not.toBe(''));

      const state = new URL(mockPopup.location.href).searchParams.get('state');

      window.dispatchEvent(
        new MessageEvent('message', {
          data: {
            source: 'monocloud-auth-web-js',
            url: `http://localhost:3000/callback?code=code&state=${state}`,
          },
          source: mockPopup,
          origin: 'http://localhost:3000',
        })
      );

      await signIn;

      const session = await instance.getSession();
      expect(session?.accessTokens?.[0].accessToken).toBe('popup-at');
      expect(sessions(listener)).toEqual([undefined, session]);
      expect(listener.mock.invocationCallOrder[1]).toBeLessThan(
        postCallback.mock.invocationCallOrder[0]
      );
      fetchSpy.assert();
    });

    it('notifies the session written by a silent sign-in', async () => {
      const idToken = await generateIdToken();

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureTokenEndpoint({ accessToken: 'silent-at', idToken })
        .createSpy();

      mockWindow.assert();

      const iframe = window.document.createElement('iframe');
      vi.spyOn(window.document, 'createElement').mockReturnValue(iframe);
      vi.spyOn(iframe, 'contentWindow', 'get').mockReturnValue(
        window as unknown as Window
      );

      let iframeSrc = '';
      vi.spyOn(iframe, 'setAttribute').mockImplementation(
        (name: string, value: string) => {
          if (name === 'src') iframeSrc = value;
        }
      );

      const instance = testInstance({
        storage: mockStorage,
        validateIdToken: false,
        fetchUserinfo: false,
        postCallback: vi.fn(),
      });

      const listener = vi.fn();
      instance.onSessionChange(listener);
      await vi.waitFor(() => expect(listener).toHaveBeenCalledWith(undefined));

      const signInSilent = instance.signInSilent();

      await vi.waitFor(() => expect(iframeSrc).not.toBe(''));

      const state = new URL(iframeSrc).searchParams.get('state');

      window.dispatchEvent(
        new MessageEvent('message', {
          data: {
            source: 'monocloud-auth-web-js',
            url: `http://localhost:3000/callback?code=code&state=${state}`,
          },
          source: window,
          origin: 'http://localhost:3000',
        })
      );

      const session = await signInSilent;

      expect(session.accessTokens?.[0].accessToken).toBe('silent-at');
      expect(sessions(listener)).toEqual([undefined, session]);
      fetchSpy.assert();
    });

    it('notifies the removals made by a popup sign-out before postCallback runs', async () => {
      const fetchSpy = fetchBuilder().configureMetadata().createSpy();

      mockWindow.assert();

      const mockPopup = {
        close: vi.fn(),
        closed: false,
        location: { href: '' },
      } as unknown as Window;

      vi.spyOn(window, 'open').mockReturnValue(mockPopup);

      await setSession(mockStorage, storedSession());

      const postCallback = vi.fn();

      const instance = testInstance({
        storage: mockStorage,
        signOutPath: undefined,
        postCallback,
      });

      const listener = vi.fn();
      instance.onSessionChange(listener);
      await vi.waitFor(() => expect(listener).toHaveBeenCalledTimes(1));

      const stored = await instance.getSession();

      const signOut = instance.signOut({ mode: 'popup' });

      await vi.waitFor(() =>
        expect(mockPopup.location.href).toContain(
          'https://example.com/connect/endsession'
        )
      );

      const state = new URL(mockPopup.location.href).searchParams.get('state');

      window.dispatchEvent(
        new MessageEvent('message', {
          data: {
            source: 'monocloud-auth-web-js',
            url: `http://localhost:3000?state=${state}`,
          },
          source: mockPopup,
          origin: 'http://localhost:3000',
        })
      );

      await signOut;

      expect(sessions(listener)).toEqual([stored, undefined, undefined]);
      expect(listener.mock.invocationCallOrder[2]).toBeLessThan(
        postCallback.mock.invocationCallOrder[0]
      );
      fetchSpy.assert();
    });

    it('notifies the session from a redirect sign-in callback before postCallback runs', async () => {
      const postCallback = vi.fn();
      const instance = signInCallbackClient({ postCallback });

      const listener = vi.fn();
      instance.onSessionChange(listener);

      await instance.processCallback();

      const session = await instance.getSession();
      expect(session?.accessTokens?.[0].accessToken).toBe('new-at');
      expect(listener).toHaveBeenCalledExactlyOnceWith(session);
      expect(listener.mock.invocationCallOrder[0]).toBeLessThan(
        postCallback.mock.invocationCallOrder[0]
      );
    });

    it('notifies the removal from a redirect sign-out callback before postCallback runs', async () => {
      mockWindow.setSearch('?state=state').setPathname('/signout').assert();

      const state: CallbackState = {
        mode: 'redirect',
        signOut: true,
        state: 'state',
      };

      mockStorage.setCallbackState(state);
      await setSession(mockStorage, storedSession());

      const postCallback = vi.fn();

      const instance = testInstance({
        storage: mockStorage,
        signOutPath: '/signout',
        postCallback,
      });

      const listener = vi.fn();
      instance.onSessionChange(listener);

      await instance.processCallback();

      expect(listener).toHaveBeenCalledExactlyOnceWith(undefined);
      expect(listener.mock.invocationCallOrder[0]).toBeLessThan(
        postCallback.mock.invocationCallOrder[0]
      );
      mockStorage.expectNoSession();
    });
  });

  describe('initial session', () => {
    it('delivers the stored session to a new listener once, never synchronously', async () => {
      await setSession(mockStorage, storedSession());

      const instance = testInstance({ storage: mockStorage });

      const listener = vi.fn();
      instance.onSessionChange(listener);

      expect(listener).not.toHaveBeenCalled();

      await flush();

      expect(listener).toHaveBeenCalledExactlyOnceWith(
        await instance.getSession()
      );
    });

    it('drops the initial read when a write is notified while it is in flight', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureRefreshToken(refreshResponse('rt', '1'))
        .createSpy();

      await setSession(mockStorage, storedSession());

      const instance = testInstance({
        storage: mockStorage,
        fetchUserinfo: false,
      });

      const release = mockStorage.holdNextRead();

      const listener = vi.fn();
      instance.onSessionChange(listener);

      await instance.refreshSession();
      const refreshed = await instance.getSession();

      release();
      await flush();

      expect(refreshed?.refreshToken).toBe('rt-1');
      expect(listener).toHaveBeenCalledExactlyOnceWith(refreshed);
      fetchSpy.assert();
    });

    it('stops notifying a listener once it unsubscribes, including a pending initial read', async () => {
      await setSession(mockStorage, storedSession());

      const instance = testInstance({ storage: mockStorage });

      const pending = vi.fn();
      const unsubscribePending = instance.onSessionChange(pending);
      unsubscribePending();

      const listener = vi.fn();
      const unsubscribe = instance.onSessionChange(listener);
      await flush();

      unsubscribe();
      await instance.signOut({ federatedSignOut: false });
      await flush();

      expect(pending).not.toHaveBeenCalled();
      expect(listener).toHaveBeenCalledExactlyOnceWith(
        expect.objectContaining({ refreshToken: 'rt' })
      );
    });

    it('treats each subscription of the same listener separately', async () => {
      const instance = testInstance({ storage: mockStorage });

      const listener = vi.fn();
      const unsubscribe = instance.onSessionChange(listener);
      instance.onSessionChange(listener);
      await flush();

      unsubscribe();
      await instance.signOut({ federatedSignOut: false });

      expect(sessions(listener)).toEqual([undefined, undefined, undefined]);
    });

    it('delivers undefined and logs the error when the stored session cannot be read', async () => {
      const consoleError = vi
        .spyOn(console, 'error')
        .mockImplementation(() => {});

      await mockStorage.setItem(sessionKey(), '{ malformed_json');

      const instance = testInstance({ storage: mockStorage });

      const listener = vi.fn();
      instance.onSessionChange(listener);
      await flush();

      expect(listener).toHaveBeenCalledExactlyOnceWith(undefined);
      expect(consoleError).toHaveBeenCalledWith(expect.any(SyntaxError));
    });
  });

  describe('redirect callback in flight', () => {
    it('delivers the exchange result instead of the pre-callback session when processCallback() runs first', async () => {
      const exchange = deferred();
      const instance = signInCallbackClient({
        onSessionCreating: () => exchange.promise,
      });

      const callback = instance.processCallback();

      const listener = vi.fn();
      instance.onSessionChange(listener);
      await flush();

      expect(listener).not.toHaveBeenCalled();

      exchange.resolve();
      await callback;

      const session = await instance.getSession();
      expect(session).toBeDefined();
      expect(listener).toHaveBeenCalledExactlyOnceWith(session);
    });

    it('delivers the exchange result instead of the pre-callback session when the listener subscribes first in the same tick', async () => {
      const exchange = deferred();
      const instance = signInCallbackClient({
        onSessionCreating: () => exchange.promise,
      });

      const listener = vi.fn();
      instance.onSessionChange(listener);

      const callback = instance.processCallback();
      await flush();

      expect(listener).not.toHaveBeenCalled();

      exchange.resolve();
      await callback;

      const session = await instance.getSession();
      expect(session).toBeDefined();
      expect(listener).toHaveBeenCalledExactlyOnceWith(session);
    });

    it('delivers the stored session once a failed exchange settles, before processCallback() rejects', async () => {
      await setSession(mockStorage, storedSession());

      const exchange = deferred();
      const instance = signInCallbackClient({
        onSessionCreating: () => exchange.promise,
      });

      const rejected = vi.fn();
      const callback = instance.processCallback().catch(rejected);

      const listener = vi.fn();
      instance.onSessionChange(listener);
      await flush();

      expect(listener).not.toHaveBeenCalled();

      exchange.reject(new Error('exchange failed'));
      await callback;

      expect(rejected).toHaveBeenCalledExactlyOnceWith(
        expect.objectContaining({ message: 'exchange failed' })
      );
      expect(listener).toHaveBeenCalledExactlyOnceWith(
        await instance.getSession()
      );
      expect(listener.mock.calls[0][0]).toEqual(
        expect.objectContaining({ refreshToken: 'rt' })
      );
      expect(listener.mock.invocationCallOrder[0]).toBeLessThan(
        rejected.mock.invocationCallOrder[0]
      );
    });

    it('gives a listener added during postCallback the new session without waiting for postCallback', async () => {
      const navigation = deferred();
      const late = vi.fn();

      const instance: MonoCloudWebJSClient = signInCallbackClient({
        postCallback: async () => {
          instance.onSessionChange(late);
          await navigation.promise;
        },
      });

      const callback = instance.processCallback();

      await vi.waitFor(() => expect(late).toHaveBeenCalledTimes(1));

      const session = await instance.getSession();
      expect(session).toBeDefined();
      expect(late).toHaveBeenCalledWith(session);

      navigation.resolve();
      await callback;
    });

    it('makes a concurrent processCallback() settle with the in-flight exchange', async () => {
      const exchange = deferred();
      const postCallback = vi.fn();
      const instance = signInCallbackClient({
        onSessionCreating: () => exchange.promise,
        postCallback,
      });

      const first = instance.processCallback();
      const settled = vi.fn();
      const second = instance.processCallback().then(settled);
      await flush();

      expect(settled).not.toHaveBeenCalled();

      const listener = vi.fn();
      instance.onSessionChange(listener);

      exchange.resolve();
      await Promise.all([first, second]);

      expect(await instance.getSession()).toBeDefined();
      expect(postCallback).toHaveBeenCalledTimes(1);
      expect(listener.mock.invocationCallOrder[0]).toBeLessThan(
        settled.mock.invocationCallOrder[0]
      );
    });

    it('rejects a concurrent processCallback() with the in-flight exchange error', async () => {
      const exchange = deferred();
      const instance = signInCallbackClient({
        onSessionCreating: () => exchange.promise,
      });

      const first = instance.processCallback();
      const second = instance.processCallback();

      exchange.reject(new Error('exchange failed'));

      const results = await Promise.allSettled([first, second]);

      expect(results).toEqual([
        {
          status: 'rejected',
          reason: expect.objectContaining({ message: 'exchange failed' }),
        },
        {
          status: 'rejected',
          reason: expect.objectContaining({ message: 'exchange failed' }),
        },
      ]);
    });
  });

  describe('processCallback() settlement', () => {
    it('settles only after a listener added in the same tick receives its session', async () => {
      const instance = testInstance({ storage: mockStorage });

      const release = mockStorage.holdNextRead();

      const settled = vi.fn();
      const callback = instance.processCallback().then(settled);

      const listener = vi.fn();
      instance.onSessionChange(listener);
      await flush();

      expect(settled).not.toHaveBeenCalled();
      expect(listener).not.toHaveBeenCalled();

      release();
      await callback;

      expect(listener).toHaveBeenCalledExactlyOnceWith(undefined);
      expect(listener.mock.invocationCallOrder[0]).toBeLessThan(
        settled.mock.invocationCallOrder[0]
      );
    });

    it('rejects only after a listener added in the same tick receives its session', async () => {
      vi.spyOn(window.sessionStorage, 'getItem').mockReturnValueOnce(
        '{ malformed_json'
      );

      await setSession(mockStorage, storedSession());

      const instance = testInstance({ storage: mockStorage });

      const rejected = vi.fn();
      const callback = instance.processCallback().catch(rejected);

      const listener = vi.fn();
      instance.onSessionChange(listener);

      await callback;

      expect(rejected).toHaveBeenCalledExactlyOnceWith(expect.any(SyntaxError));
      expect(listener).toHaveBeenCalledExactlyOnceWith(
        await instance.getSession()
      );
      expect(listener.mock.invocationCallOrder[0]).toBeLessThan(
        rejected.mock.invocationCallOrder[0]
      );
    });
  });

  describe('listener errors', () => {
    it('keeps a throwing listener from breaking the write, the action or other listeners', async () => {
      const consoleError = vi
        .spyOn(console, 'error')
        .mockImplementation(() => {});

      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureRefreshToken(refreshResponse('rt', '1'))
        .createSpy();

      await setSession(mockStorage, storedSession());

      const instance = testInstance({
        storage: mockStorage,
        fetchUserinfo: false,
      });

      const failure = new Error('listener failed');
      const throwing = vi.fn(() => {
        throw failure;
      });
      const listener = vi.fn();

      instance.onSessionChange(throwing);
      instance.onSessionChange(listener);
      await flush();

      await expect(instance.refreshSession()).resolves.toBeUndefined();

      const refreshed = await instance.getSession();
      expect(refreshed?.refreshToken).toBe('rt-1');
      expect(throwing).toHaveBeenCalledTimes(2);
      expect(sessions(listener)).toEqual([
        expect.objectContaining({ refreshToken: 'rt' }),
        refreshed,
      ]);
      expect(consoleError).toHaveBeenCalledTimes(2);
      expect(consoleError).toHaveBeenCalledWith(failure);
      fetchSpy.assert();
    });
  });

  describe('no write, no notification', () => {
    it('stays silent when getTokens() returns a valid token without refreshing', async () => {
      await setSession(mockStorage, storedSession());

      const instance = testInstance({ storage: mockStorage });

      const listener = vi.fn();
      instance.onSessionChange(listener);
      await flush();

      await instance.getTokens();
      await flush();

      expect(listener).toHaveBeenCalledTimes(1);
    });

    it('stays silent when a refresh fails', async () => {
      const fetchSpy = fetchBuilder()
        .configureMetadata()
        .configureRefreshToken({
          body: 'grant_type=refresh_token&refresh_token=rt',
          responseCode: 400,
          error: 'invalid_grant',
          error_description: 'expired',
        })
        .createSpy();

      await setSession(mockStorage, storedSession());

      const instance = testInstance({ storage: mockStorage });

      const listener = vi.fn();
      instance.onSessionChange(listener);
      await flush();

      await expect(instance.refreshSession()).rejects.toThrow();
      await flush();

      expect(listener).toHaveBeenCalledTimes(1);
      fetchSpy.assert();
    });

    it('stays silent when processCallback() finds no callback to process', async () => {
      const instance = testInstance({ storage: mockStorage });

      const listener = vi.fn();
      instance.onSessionChange(listener);
      await flush();

      await instance.processCallback();
      await flush();

      expect(listener).toHaveBeenCalledExactlyOnceWith(undefined);
    });
  });
});
