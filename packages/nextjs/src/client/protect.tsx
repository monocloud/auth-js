/* eslint-disable react/display-name */
'use client';

import React, { ComponentType, JSX, useEffect } from 'react';
import type { MonoCloudUser } from '@monocloud/auth-node-core';
import { isUserInGroup } from '@monocloud/auth-node-core/utils';
import { useAuth } from './use-auth';
import { ExtraAuthParams, GroupOptions } from '../types';

/**
 * Options for configuring page protection.
 */
export type ProtectPageOptions = {
  /**
   *The url where the user will be redirected to after sign in
   */
  returnUrl?: string;

  /**
   * A custom react element to render when the user is not authenticated or is not a member of the specified groups.
   */
  onAccessDenied?: (user?: MonoCloudUser) => JSX.Element;

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
  onError?: (error: Error) => JSX.Element;
} & GroupOptions;

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
  options?: ProtectPageOptions
): JSX.Element => {
  /* v8 ignore else -- @preserve */
  if (options?.onError) {
    return options.onError(error);
  }

  /* v8 ignore next -- @preserve */
  throw error;
};

/**
 * Function to protect a client rendered page component.
 * Ensures that only authenticated users can access the component.
 * 
 * **Note⚠️: Since `window.location` is set as `returnUrl` query param by default, you need to set the env `MONOCLOUD_AUTH_ALLOW_QUERY_PARAM_OVERRIDES=true` or `allowQueryParamOverrides` should be `true` in the client initialization for returning to the same page.**
 *
 * @param Component - The component to protect.
 * @param options - The options.
 *
 * @returns Protected client rendered page component.
 *
 * @example App Router
 *
 * ```tsx
 * "use client";
 *
 * import { protectPage } from "@monocloud/auth-nextjs/client";
 *
 * export default protectPage(function Home() {
 *   return <>You are signed in</>;
 * });
 * ```
 *
 * @example App Router with options
 * 
 * See {@link ProtectPageOptions} for more options.
 *
 * ```tsx
 * "use client";
 *
 * import { protectPage } from "@monocloud/auth-nextjs/client";
 *
 * export default protectPage(
 *   function Home() {
 *     return <>You are signed in</>;
 *   },
 *   { returnUrl: "/dashboard", authParams: { loginHint: "username" } }
 * );
 * ```

* @example Pages Router
 *
 * ```tsx
 * import { protectPage } from "@monocloud/auth-nextjs/client";
 *
 * export default protectPage(function Home() {
 *   return <>You are signed in</>;
 * });
 * ```
 *
 * @example Pages Router with options
 * 
 * See {@link ProtectPageOptions} for more options.
 *
 * ```tsx
 * import { protectPage } from "@monocloud/auth-nextjs/client";
 *
 * export default protectPage(
 *   function Home() {
 *     return <>You are signed in</>;
 *   },
 *   { returnUrl: "/dashboard", authParams: { loginHint: "username" } }
 * );
 * ```
 */
export const protectPage = <P extends object>(
  Component: ComponentType<P & { user: MonoCloudUser }>,
  options?: ProtectPageOptions
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
        const { onAccessDenied = (): JSX.Element => <div>Access Denied</div> } =
          options;
        return onAccessDenied(user);
      }

      return <Component user={user} {...props} />;
    }

    return null;
  };
};
