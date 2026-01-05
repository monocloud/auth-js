'use client';

import type { MonoCloudUser } from '@monocloud/auth-node-core';
import useSWR from 'swr';

/**
 * Authentication State returned by `useAuth` hook.
 */
export interface AuthState {
  /**
   * Flag indicating if the authentication state is still loading.
   */
  isLoading: boolean;
  /**
   * Flag indicating if the user is authenticated.
   */
  isAuthenticated: boolean;
  /**
   * Error encountered during authentication, if any.
   */
  error?: Error;
  /**
   *  The authenticated user's information, if available.
   */
  user?: MonoCloudUser;
  /**
   * Function to refetch the authentication state.
   *
   */
  refetch: (refresh?: boolean) => void;
}

const fetchUser = async (url: string): Promise<MonoCloudUser | undefined> => {
  const res = await fetch(url, { credentials: 'include' });

  if (res.status === 204) {
    return undefined;
  }

  if (res.ok) {
    return res.json();
  }

  throw new Error('Failed to fetch user');
};

/**
 *
 * Hook for getting the user's profile on client components
 *
 * @returns Authentication State
 *
 * @example App Router
 *
 * ```tsx
 * "use client";
 *
 * import { useAuth } from "@monocloud/auth-nextjs/client";
 *
 * export default function Home() {
 *   const { user } = useAuth();
 *
 *   return <>User Id: {user?.sub}</>;
 * }
 * ```
 *
 * @example App Router - Refetch user from Userinfo endpoint
 *
 * Calling `refetch(true)` will force refresh the user's profile from the userinfo endpoint.
 * If you do not intent to refersh from your tenants userinfo endpoint, use just `refetch()`
 *
 * **Note⚠️: You need to set the env `MONOCLOUD_AUTH_ALLOW_QUERY_PARAM_OVERRIDES=true` or `allowQueryParamOverrides` should be `true` in the client initialization for force refresh to work**
 *
 * ```tsx
 * "use client";
 *
 * import { useAuth } from "@monocloud/auth-nextjs/client";
 *
 * export default function Home() {
 *   const { user, refetch } = useAuth();
 *
 *   return (
 *     <>
 *       <pre>{JSON.stringify(user)}</pre>
 *       <button onClick={() => refetch(true)}>Refresh</button>
 *     </>
 *   );
 * }
 * ```
 *
 * @example Pages Router
 *
 * ```tsx
 * import { useAuth } from "@monocloud/auth-nextjs/client";
 *
 * export default function Home() {
 *   const { user } = useAuth();
 *
 *   return <>User Id: {user?.sub}</>;
 * }
 * ```
 *
 * @example Pages Router - Refetch user from Userinfo endpoint
 *
 *  Calling `refetch(true)` will force refresh the user's profile from the userinfo endpoint.
 * If you do not intent to refersh from your tenants userinfo endpoint, use just `refetch()`
 *
 * **Note⚠️: You need to set the env `MONOCLOUD_AUTH_ALLOW_QUERY_PARAM_OVERRIDES=true` or `allowQueryParamOverrides` should be `true` in the client initialization for force refresh to work**
 *
 * ```tsx
 * import { useAuth } from "@monocloud/auth-nextjs/client";
 *
 * export default function Home() {
 *   const { user, refetch } = useAuth();
 *
 *   return (
 *     <>
 *       <pre>{JSON.stringify(user)}</pre>
 *       <button onClick={() => refetch(true)}>Refresh</button>
 *     </>
 *   );
 * }
 * ```
 *
 */
export const useAuth = (): AuthState => {
  const key =
    process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_USER_INFO_URL ??
    // eslint-disable-next-line no-underscore-dangle
    `${process.env.__NEXT_ROUTER_BASEPATH ?? ''}/api/auth/userinfo`;

  const { data, error, isLoading, mutate } = useSWR<MonoCloudUser | undefined>(
    key,
    fetchUser
  );

  const refetch = (refresh?: boolean): void => {
    const url = new URL(key, 'https://dummy');
    if (refresh) {
      url.searchParams.set('refresh', 'true');
    }

    void mutate(async () => await fetchUser(url.pathname + url.search), {
      revalidate: false,
    });
  };

  if (error) {
    return {
      user: undefined,
      isLoading: false,
      isAuthenticated: false,
      error: error as Error,
      refetch,
    };
  }

  if (data) {
    return {
      user: data,
      isLoading,
      isAuthenticated: !!data && Object.keys(data).length > 0,
      error: undefined,
      refetch,
    };
  }

  return {
    user: undefined,
    isLoading,
    isAuthenticated: false,
    error: undefined,
    /* v8 ignore next -- @preserve */
    refetch: (): void => {},
  };
};
