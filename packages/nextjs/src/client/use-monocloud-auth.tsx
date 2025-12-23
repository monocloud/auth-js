'use client';

import { MonoCloudUser } from '@monocloud/auth-node-core';
import useSWR from 'swr';

/**
 * Authentication State returned by `useMonoCloudAuth` hook.
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
   */
  refetch?: () => void;
}

/**
 * @returns Authentication State
 */
export const useMonoCloudAuth = (): AuthState => {
  const { data, error, isLoading, mutate } = useSWR<MonoCloudUser | undefined>(
    process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_USER_INFO_URL ??
      // eslint-disable-next-line no-underscore-dangle
      `${process.env.__NEXT_ROUTER_BASEPATH ?? ''}/api/auth/userinfo`,
    async (url: string) => {
      const res = await fetch(url, { credentials: 'include' });

      if (res.status === 204) {
        return undefined;
      }

      if (res.ok) {
        return res.json();
      }

      throw new Error('Failed to fetch user');
    }
  );

  if (error) {
    return {
      user: undefined,
      isLoading: false,
      isAuthenticated: false,
      error: error as Error,
      refetch: () => mutate(),
    };
  }

  if (data) {
    return {
      user: data,
      isLoading,
      isAuthenticated: !!data && Object.keys(data).length > 0,
      error: undefined,
      refetch: () => mutate(),
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
