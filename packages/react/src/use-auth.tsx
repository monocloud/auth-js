'use client';

import { MonoCloudJsError } from '@monocloud/auth-web-js';
import { useContext } from 'react';
import { MonoCloudAuthContext } from './context';
import type { MonoCloudAuth } from './types';
import type { MonoCloudAuthProvider } from './monocloud-auth-provider';

/**
 * `useAuth()` is a client-side hook that exposes the current authentication
 * state and actions provided by {@link MonoCloudAuthProvider}.
 *
 * @example Reading the authentication state
 *
 * ```tsx:src/Profile.tsx tab="Reading the authentication state" tab-group="useAuth"
 * "use client";
 *
 * import { useAuth } from "@monocloud/auth-react";
 *
 * export default function Home() {
 *   const { isLoading, isAuthenticated, user } = useAuth();
 *
 *   if (isLoading) {
 *     return <>Loading...</>;
 *   }
 *
 *   if (!isAuthenticated) {
 *     return <>Not signed in</>;
 *   }
 *
 *   return <>User Id: {user?.sub}</>;
 * }
 * ```
 *
 * @example Triggering actions
 *
 * ```tsx:src/Profile.tsx tab="Triggering actions" tab-group="useAuth"
 * "use client";
 *
 * import { useAuth } from "@monocloud/auth-react";
 *
 * export default function Account() {
 *   const { signOut, refetchUserInfo } = useAuth();
 *
 *   return (
 *     <>
 *       <button onClick={() => refetchUserInfo()}>Refresh profile</button>
 *       <button onClick={() => signOut()}>Sign out</button>
 *     </>
 *   );
 * }
 * ```
 *
 * @returns The current {@link MonoCloudAuth}.
 *
 * @category Hooks
 */
export const useAuth = (): MonoCloudAuth => {
  const context = useContext(MonoCloudAuthContext);

  if (!context) {
    throw new MonoCloudJsError(
      'useAuth() can only be used inside a <MonoCloudAuthProvider>...</MonoCloudAuthProvider>.'
    );
  }

  return context;
};
