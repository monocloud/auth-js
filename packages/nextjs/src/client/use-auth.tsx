'use client';

import type { MonoCloudUser } from '@monocloud/auth-node-core';
import useSWR from 'swr';

/**
 * Authentication State returned by `useAuth` hook.
 *
 * @category Types
 */
export interface AuthenticationState {
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
 * `useAuth()` is a client-side hook that provides access to the current authentication state.
 *
 * It can only be used inside **Client Components**.
 *
 * @example Basic Usage
 * ```tsx title="Basic Usage"
 * "use client";
 *
 * import { useAuth } from "@monocloud/auth-nextjs/client";
 *
 * export default function Home() {
 *   const { user, isAuthenticated } = useAuth();
 *
 *   if (!isAuthenticated) {
 *     return <>Not signed in</>;
 *   }
 *
 *   return <>User Id: {user?.sub}</>;
 * }
 * ```
 *
 * @example Refetch user
 *
 * Calling `refetch(true)` forces a refresh of the user profile from the UserInfo endpoint.
 * Calling `refetch()` refreshes authentication state without forcing a UserInfo request.
 *
 * ```tsx title="Refetch User"
 * "use client";
 *
 * import { useAuth } from "@monocloud/auth-nextjs/client";
 *
 * export default function Home() {
 *   const { user, refetch } = useAuth();
 *
 *   return (
 *     <>
 *       <pre>{JSON.stringify(user, null, 2)}</pre>
 *       <button onClick={() => refetch(true)}>Refresh Profile</button>
 *     </>
 *   );
 * }
 * ```
 *
 * @returns
 *
 * @category Hooks
 */
export const useAuth = (): AuthenticationState => {
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
