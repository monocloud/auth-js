// eslint-disable-next-line import/no-extraneous-dependencies
import { expect } from 'vitest';
import { MockStorage } from '@monocloud/auth-test-utils';
import type {
  CallbackState,
  IStorage,
  InteractionMode,
  MonoCloudWebJSClientOptions,
} from '../src';
import { AUTH_CONSTANTS } from '../src/constants';
import { MonoCloudWebJSClient } from '../src';

export const ensureLockManagerStub = (): void => {
  if (!(globalThis as any).LockManager) {
    (globalThis as any).LockManager = class LockManager {};
  }
  (globalThis as any).navigator = (globalThis as any).navigator ?? {};
};

export const testInstance = (
  options?: Partial<MonoCloudWebJSClientOptions>
): MonoCloudWebJSClient => {
  const deafultOptions = {
    appUrl: 'http://localhost:3000',
    tenantDomain: 'https://example.com',
    callbackPath: '/callback',
    signOutCallbackPath: '/signout',
    clientId: 'clientId',
  };

  const instance = new MonoCloudWebJSClient({
    ...deafultOptions,
    ...options,
  } as MonoCloudWebJSClientOptions);

  return instance;
};

export const callbackStateKey = (): string =>
  // @ts-expect-error We are accessing the custom key from window
  `${AUTH_CONSTANTS.CALLBACK_KEY}.clientId${window.callbackStateKey ? `.${window.callbackStateKey}` : ''}`;

export const sessionKey = (): string =>
  // @ts-expect-error We are accessing the custom key from window
  `${AUTH_CONSTANTS.SESSION_KEY}.clientId${window.sessionKey ? `.${window.sessionKey}` : ''}`;

export class VanillaJsMockStorage extends MockStorage implements IStorage {
  setCallbackState(state: unknown): void {
    window.sessionStorage.setItem(callbackStateKey(), JSON.stringify(state));
  }

  getCallbackState(): CallbackState | undefined {
    const raw = window.sessionStorage.getItem(callbackStateKey());
    if (!raw) return undefined;
    return JSON.parse(raw) as CallbackState;
  }

  expectSession(session?: unknown): VanillaJsMockStorage {
    expect(this.store[sessionKey()]).toBeTypeOf('string');
    if (session) {
      expect(JSON.parse(this.store[sessionKey()] ?? '')).toEqual(session);
    }
    return this;
  }

  expectCallbackState(): VanillaJsMockStorage {
    expect(window.sessionStorage.getItem(callbackStateKey())).toBeTypeOf(
      'string'
    );
    return this;
  }

  expectNoSession(): VanillaJsMockStorage {
    expect(this.store[sessionKey()]).toBeUndefined();
    return this;
  }

  expectCallbackStateRemoved(): VanillaJsMockStorage {
    expect(window.sessionStorage.getItem(callbackStateKey())).toBe(null);
    return this;
  }

  expectCallbackStateCodeVerifier(): VanillaJsMockStorage {
    const state: CallbackState = JSON.parse(
      window.sessionStorage.getItem(callbackStateKey()) ?? ''
    );

    expect(state.codeVerifier).toBeTypeOf('string');
    return this;
  }

  expectCallbackStateState(): VanillaJsMockStorage {
    const state: CallbackState = JSON.parse(
      window.sessionStorage.getItem(callbackStateKey()) ?? ''
    );

    expect(state.state).toBeTypeOf('string');
    return this;
  }

  expectCallbackStateMode(mode: InteractionMode): VanillaJsMockStorage {
    const state: CallbackState = JSON.parse(
      window.sessionStorage.getItem(callbackStateKey()) ?? ''
    );

    expect(state.mode).toBe(mode);
    return this;
  }

  expectCallbackStateMaxAge(maxAge: number | undefined): VanillaJsMockStorage {
    const state: CallbackState = JSON.parse(
      window.sessionStorage.getItem(callbackStateKey()) ?? ''
    );

    expect(state.maxAge).toBe(maxAge);
    return this;
  }

  expectCallbackStateNonce(): VanillaJsMockStorage {
    const state: CallbackState = JSON.parse(
      window.sessionStorage.getItem(callbackStateKey()) ?? ''
    );

    expect(state.nonce).toBeTypeOf('string');
    return this;
  }

  expectCallbackStateSignOut(
    signOut: boolean | undefined
  ): VanillaJsMockStorage {
    const state: CallbackState = JSON.parse(
      window.sessionStorage.getItem(callbackStateKey()) ?? ''
    );

    expect(state.signOut).toBe(signOut);
    return this;
  }

  expectCallbackStateResponseType(
    responseType: string | undefined
  ): VanillaJsMockStorage {
    const state = this.getCallbackState();
    expect(state?.responseType).toBe(responseType);
    return this;
  }

  expectCallbackStateResource(
    resource: string | undefined
  ): VanillaJsMockStorage {
    const state = this.getCallbackState();
    expect(state?.resource).toBe(resource);
    return this;
  }

  expectCallbackStateScopes(scopes: string | undefined): VanillaJsMockStorage {
    const state = this.getCallbackState();
    expect(state?.scopes).toBe(scopes);
    return this;
  }
}

export const setSession = async (
  storage: IStorage,
  session: unknown
): Promise<void> => {
  await storage.setItem(sessionKey(), JSON.stringify(session));
};
