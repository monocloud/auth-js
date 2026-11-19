'use client';

import {
  MonoCloudWebJSClient,
  type GetTokensOptions,
  type MonoCloudSession,
  type MonoCloudTokens,
  type RefreshOptions,
  type SignInOptions,
  type SignInSilentOptions,
  type SignOutOptions,
} from '@monocloud/auth-web-js';
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  MonoCloudAuthContext,
  MonoCloudClientContext,
  MonoCloudProcessCallbackContext,
} from './context';
import type {
  AuthState,
  MonoCloudAuth,
  MonoCloudAuthProviderProps,
} from './types';

const initialState: AuthState = {
  isLoading: true,
  isAuthenticated: false,
};

/**
 * `<MonoCloudAuthProvider>` initializes the MonoCloud JavaScript client and makes
 * the authentication state and actions available through {@link useAuth}.
 *
 * @example Basic setup
 *
 * ```tsx:src/main.tsx tab="Basic setup" tab-group="MonoCloudAuthProvider"
 * "use client";
 *
 * import { MonoCloudAuthProvider } from "@monocloud/auth-react";
 *
 * export default function Root() {
 *   return (
 *     <MonoCloudAuthProvider
 *       tenantDomain="https://your-tenant-domain"
 *       clientId="your-client-id"
 *     >
 *       <App />
 *     </MonoCloudAuthProvider>
 *   );
 * }
 * ```
 *
 * @example Client-side router navigation
 *
 * ```tsx:src/main.tsx tab="Client-side router navigation" tab-group="MonoCloudAuthProvider"
 * "use client";
 *
 * import { MonoCloudAuthProvider } from "@monocloud/auth-react";
 * import { useNavigate } from "react-router";
 *
 * export default function Root() {
 *   const navigate = useNavigate();
 *
 *   return (
 *     <MonoCloudAuthProvider
 *       tenantDomain="https://your-tenant-domain"
 *       clientId="your-client-id"
 *       autoProcessCallback={false}
 *       postCallback={state => navigate(state.returnUrl ?? "/")}
 *     >
 *       <App />
 *     </MonoCloudAuthProvider>
 *   );
 * }
 * ```
 *
 * @param props - Props for configuring the provider and the underlying client.
 * @returns The provider element wrapping `children`.
 *
 * @category Components
 */
export const MonoCloudAuthProvider = ({
  children,
  autoProcessCallback = true,
  ...clientOptions
}: MonoCloudAuthProviderProps): React.JSX.Element => {
  const [state, setState] = useState<AuthState>(initialState);

  const [client] = useState<MonoCloudWebJSClient>(
    () => new MonoCloudWebJSClient(clientOptions)
  );

  useEffect(
    () =>
      client.onSessionChange(session =>
        setState({
          isLoading: false,
          isAuthenticated: !!session,
          user: session?.user,
          session,
          error: undefined,
        })
      ),
    [client]
  );

  const processCallback = useCallback(async (): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));

    try {
      await client.processCallback();
      setState(prev => ({ ...prev, isLoading: false }));
    } catch (e) {
      setState(prev => ({ ...prev, isLoading: false, error: e as Error }));
      throw e;
    }
  }, [client]);

  const initialized = useRef(false);
  useEffect(() => {
    /* v8 ignore start -- StrictMode double-invocation guard */
    if (initialized.current) {
      return;
    }
    /* v8 ignore stop */
    initialized.current = true;

    if (autoProcessCallback) {
      processCallback().catch(() => {});
    }
  }, [autoProcessCallback, processCallback]);

  const signIn = useCallback(
    async (signInOptions?: SignInOptions): Promise<void> => {
      setState(prev => ({ ...prev, isLoading: true }));
      try {
        await client.signIn(signInOptions);
        setState(prev => ({ ...prev, isLoading: false }));
      } catch (e) {
        setState(prev => ({ ...prev, isLoading: false, error: e as Error }));
      }
    },
    [client]
  );

  const signOut = useCallback(
    async (signOutOptions?: SignOutOptions): Promise<void> => {
      setState(prev => ({ ...prev, isLoading: true }));
      try {
        await client.signOut(signOutOptions);
        setState(prev => ({ ...prev, isLoading: false }));
      } catch (e) {
        setState(prev => ({ ...prev, isLoading: false, error: e as Error }));
      }
    },
    [client]
  );

  const signInSilent = useCallback(
    (signInSilentOptions?: SignInSilentOptions): Promise<MonoCloudSession> =>
      client.signInSilent(signInSilentOptions),
    [client]
  );

  const refreshSession = useCallback(
    (refreshOptions?: RefreshOptions): Promise<void> =>
      client.refreshSession(refreshOptions),
    [client]
  );

  const refetchUserInfo = useCallback(
    (): Promise<void> => client.refetchUserInfo(),
    [client]
  );

  const getTokens = useCallback(
    (options?: GetTokensOptions): Promise<MonoCloudTokens> =>
      client.getTokens(options),
    [client]
  );

  const value = useMemo<MonoCloudAuth>(
    () => ({
      ...state,
      signIn,
      signOut,
      signInSilent,
      refreshSession,
      refetchUserInfo,
      getTokens,
    }),
    [
      state,
      signIn,
      signOut,
      signInSilent,
      refreshSession,
      refetchUserInfo,
      getTokens,
    ]
  );

  return (
    <MonoCloudClientContext.Provider value={client}>
      <MonoCloudProcessCallbackContext.Provider value={processCallback}>
        <MonoCloudAuthContext.Provider value={value}>
          {children}
        </MonoCloudAuthContext.Provider>
      </MonoCloudProcessCallbackContext.Provider>
    </MonoCloudClientContext.Provider>
  );
};
