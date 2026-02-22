/* eslint-disable react/display-name */
'use client';

import React, { ComponentType, useEffect } from 'react';
import type { MonoCloudUser } from '@monocloud/auth-node-core';
import { isUserInGroup } from '@monocloud/auth-node-core/utils';
import { useAuth } from './use-auth';
import { ExtraAuthParams, GroupOptions } from '../types';
import type { MonoCloudNextClient } from '../monocloud-next-client';

/**
 * Options for configuring page protection.
 *
 * @category Types
 */
export interface ProtectClientPageOptions extends GroupOptions {
  /**
   * The URL where the user will be redirected to after sign in.
   */
  returnUrl?: string;

  /**
   * A custom react element to render when the user is not authenticated.
   */
  onAccessDenied?: () => React.ReactNode;

  /**
   * A custom react element to render when the user is authenticated but does not belong to the required groups.
   */
  onGroupAccessDenied?: (user: MonoCloudUser) => React.ReactNode;

  /**
   * Authorization parameters to be used during authentication.
   */
  authParams?: ExtraAuthParams;

  /**
   * Callback function to handle errors.
   * If not provided, errors will be thrown.
   *
   * @param error - The error object.
   * @returns JSX element to handle the error.
   */
  onError?: (error: Error) => React.ReactNode;
}

export const redirectToSignIn = (
  options: { returnUrl?: string } & ExtraAuthParams
): void => {
  const searchParams = new URLSearchParams(window.location.search);
  searchParams.set(
    'return_url',
    options.returnUrl ?? window.location.toString()
  );

  if (options?.scopes) {
    searchParams.set('scope', options.scopes);
  }
  if (options?.resource) {
    searchParams.set('resource', options.resource);
  }

  if (options?.acrValues) {
    searchParams.set('acr_values', options.acrValues.join(' '));
  }

  if (options?.display) {
    searchParams.set('display', options.display);
  }

  if (options?.prompt) {
    searchParams.set('prompt', options.prompt);
  }

  if (options?.authenticatorHint) {
    searchParams.set('authenticator_hint', options.authenticatorHint);
  }

  if (options?.uiLocales) {
    searchParams.set('ui_locales', options.uiLocales);
  }

  if (options?.maxAge) {
    searchParams.set('max_age', options.maxAge.toString());
  }

  if (options?.loginHint) {
    searchParams.set('login_hint', options.loginHint);
  }

  window.location.assign(
    // eslint-disable-next-line no-underscore-dangle
    `${process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_SIGNIN_URL ?? `${process.env.__NEXT_ROUTER_BASEPATH ?? ''}/api/auth/signin`}?${searchParams.toString()}`
  );
};

const handlePageError = (
  error: Error,
  options?: ProtectClientPageOptions
): React.ReactNode => {
  /* v8 ignore else -- @preserve */
  if (options?.onError) {
    return options.onError(error);
  }

  /* v8 ignore next -- @preserve */
  throw error;
};

/**
 * `protectClientPage()` wraps a **client-rendered page component** and ensures that only authenticated users can access it.
 *
 * If the user is authenticated, the wrapped component receives a `user` prop.
 *
 * > This function runs on the client and controls rendering only.
 * > To enforce access before rendering (server-side), use the server {@link MonoCloudNextClient.protectPage | protectPage()} method on {@link MonoCloudNextClient}.
 *
 * @example Basic Usage
 *
 * ```tsx title="Basic Usage"
 * "use client";
 *
 * import { protectClientPage } from "@monocloud/auth-nextjs/client";
 *
 * export default protectClientPage(function Home({ user }) {
 *   return <>Signed in as {user.email}</>;
 * });
 * ```
 *
 * @example With Options
 *
 * ```tsx title="With Options"
 * "use client";
 *
 * import { protectClientPage } from "@monocloud/auth-nextjs/client";
 *
 * export default protectClientPage(
 *   function Home({ user }) {
 *     return <>Signed in as {user.email}</>;
 *   },
 *   {
 *     returnUrl: "/dashboard",
 *     authParams: { loginHint: "user@example.com" }
 *   }
 * );
 * ```
 *
 * @example Custom access denied UI
 *
 * ```tsx title="Custom access denied UI"
 * "use client";
 *
 * import { protectClientPage } from "@monocloud/auth-nextjs/client";
 *
 * export default protectClientPage(
 *   function Home({ user }) {
 *     return <>Signed in as {user.email}</>;
 *   },
 *   {
 *    onAccessDenied: () => <div>Please sign in to continue</div>
 *   }
 * );
 * ```
 *
 * @example Group protection
 *
 * ```tsx title="Group protection"
 * "use client";
 *
 * import { protectClientPage } from "@monocloud/auth-nextjs/client";
 *
 * export default protectClientPage(
 *   function Home({ user }) {
 *     return <>Welcome Admin {user.email}</>;
 *   },
 *   {
 *    groups: ["admin"],
 *    onGroupAccessDenied: (user) => <div>User {user.email} is not an admin</div>
 *   }
 * );
 * ```
 *
 * @param Component - The page component to protect
 * @typeParam P - Props of the protected component (excluding `user`).
 * @param options - Optional configuration
 * @returns A protected React component.
 *
 * @category Functions
 *
 */
export const protectClientPage = <P extends object>(
  Component: ComponentType<P & { user: MonoCloudUser }>,
  options?: ProtectClientPageOptions
): React.FC<P> => {
  return props => {
    const { user, error, isLoading } = useAuth();

    useEffect(() => {
      if (!user && !isLoading && !error) {
        if (options?.onAccessDenied) {
          return;
        }

        const authParams = options?.authParams ?? {};
        redirectToSignIn({
          returnUrl: options?.returnUrl,
          ...authParams,
        });
      }
    }, [user, isLoading, error]);

    if (error) {
      return handlePageError(error, options);
    }

    if (!user && !isLoading && options?.onAccessDenied) {
      return options.onAccessDenied();
    }

    if (user) {
      if (
        options?.groups &&
        !isUserInGroup(
          user,
          options.groups,
          options.groupsClaim ??
            process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_GROUPS_CLAIM,
          options.matchAll
        )
      ) {
        const {
          onGroupAccessDenied = (): React.ReactNode => <div>Access Denied</div>,
        } = options;
        return onGroupAccessDenied(user);
      }

      return <Component user={user} {...props} />;
    }

    return null;
  };
};
