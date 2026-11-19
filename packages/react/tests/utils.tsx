/* eslint-disable import/no-extraneous-dependencies */
import type {
  MonoCloudSession,
  MonoCloudTokens,
  MonoCloudWebJSClient,
  SessionChangeListener,
} from '@monocloud/auth-web-js';
import { render, type RenderResult } from '@testing-library/react';
import React from 'react';
import { type Mock, vi } from 'vitest';
import { MonoCloudAuthProvider } from '../src/monocloud-auth-provider';
import type { MonoCloudAuthProviderProps } from '../src/types';
import { useAuth } from '../src/use-auth';

export type MockClient = {
  [
    K in keyof Pick<
      MonoCloudWebJSClient,
      | 'processCallback'
      | 'getSession'
      | 'getTokens'
      | 'signIn'
      | 'signOut'
      | 'signInSilent'
      | 'refreshSession'
      | 'refetchUserInfo'
      | 'onSessionChange'
    >
  ]: Mock;
} & {
  oidcClient: {
    [K in keyof Pick<MonoCloudWebJSClient['oidcClient'], 'revokeToken'>]: Mock;
  };
  emit: (session?: MonoCloudSession) => void;
};

export const makeMockClient = (
  overrides: Partial<MockClient> = {}
): MockClient => {
  const listeners = new Set<SessionChangeListener>();

  const client: MockClient = {
    processCallback: vi.fn().mockResolvedValue(undefined),
    getSession: vi.fn().mockResolvedValue(undefined),
    getTokens: vi
      .fn()
      .mockResolvedValue({ isExpired: false } as MonoCloudTokens),
    signIn: vi.fn().mockResolvedValue(undefined),
    signOut: vi.fn().mockResolvedValue(undefined),
    signInSilent: vi.fn().mockResolvedValue(undefined),
    refreshSession: vi.fn().mockResolvedValue(undefined),
    refetchUserInfo: vi.fn().mockResolvedValue(undefined),
    onSessionChange: vi.fn((listener: SessionChangeListener) => {
      listeners.add(listener);
      void client.getSession().then((session?: MonoCloudSession) => {
        if (listeners.has(listener)) {
          listener(session);
        }
      });
      return () => {
        listeners.delete(listener);
      };
    }),
    emit: session => listeners.forEach(listener => listener(session)),
    oidcClient: { revokeToken: vi.fn().mockResolvedValue(undefined) },
    ...overrides,
  };

  return client;
};

export interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
}

export const deferred = <T = void,>(): Deferred<T> => {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

export const flush = (): Promise<void> =>
  new Promise(resolve => {
    setTimeout(resolve, 0);
  });

export const setMockClient = (client: MockClient): void => {
  (globalThis as Record<string, unknown>).mcMockClient = client;
};

export const getClientOptions = (): Record<string, unknown> =>
  (globalThis as Record<string, unknown>).mcMockClientOptions as Record<
    string,
    unknown
  >;

export const aSession = (
  overrides: Partial<MonoCloudSession> = {}
): MonoCloudSession =>
  ({
    user: { sub: 'user-1', email: 'user@example.com', groups: ['admin'] },
    idToken: 'id-token',
    ...overrides,
  }) as MonoCloudSession;

export const renderWithProvider = (
  ui: React.ReactNode,
  props: Partial<MonoCloudAuthProviderProps> = {}
): RenderResult =>
  render(
    <MonoCloudAuthProvider
      tenantDomain="https://tenant.us.monocloud.com"
      clientId="client-id"
      {...props}
    >
      {ui}
    </MonoCloudAuthProvider>
  );

export const AuthProbe = (): React.JSX.Element => {
  const { isLoading, isAuthenticated, user, error } = useAuth();
  return (
    <div>
      <span data-testid="loading">{String(isLoading)}</span>
      <span data-testid="authenticated">{String(isAuthenticated)}</span>
      <span data-testid="user">{user?.sub ?? ''}</span>
      <span data-testid="error">{error?.message ?? ''}</span>
    </div>
  );
};

export const ActionControls = (): React.JSX.Element => {
  const {
    signIn,
    signOut,
    signInSilent,
    refreshSession,
    refetchUserInfo,
    getTokens,
  } = useAuth();
  return (
    <div>
      <button onClick={() => void signIn({ mode: 'popup' })}>signin</button>
      <button onClick={() => void signOut({ mode: 'popup' })}>signout</button>
      <button onClick={() => void signInSilent()}>silent</button>
      <button onClick={() => void refreshSession()}>refresh</button>
      <button onClick={() => void refetchUserInfo()}>refetch</button>
      <button onClick={() => void getTokens()}>tokens</button>
    </div>
  );
};
