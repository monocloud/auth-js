'use client';

import { useEffect } from 'react';
import { redirectToSignIn } from '../../client/protect';
import { ExtraAuthParams } from '../../types';

/**
 * Props for the `<RedirectToSignIn />` Component
 */
export interface RedirectToSignInProps extends ExtraAuthParams {
  /**
   * The url where the user will be redirected to after sign in.
   */
  returnUrl?: string;
}

/**
 * A client side component that will redirect users to the sign in page.
 *
 * **Note⚠️: Since `window.location` is set as `returnUrl` query param by default, you need to set the env `MONOCLOUD_AUTH_ALLOW_QUERY_PARAM_OVERRIDES=true` or `allowQueryParamOverrides` should be `true` in the client initialization for returning to the same page.**
 *
 * @param props - The props for customizing RedirectToSignIn
 *
 * @returns
 *
 * @example App Router
 *
 * ```tsx
 * "use client";
 *
 * import { useAuth } from "@monocloud/auth-nextjs/client";
 * import { RedirectToSignIn } from "@monocloud/auth-nextjs/components/client";
 *
 * export default function Home() {
 *   const { isLoading, isAuthenticated } = useAuth();
 *
 *   if (!isLoading && !isAuthenticated) {
 *     return <RedirectToSignIn />;
 *   }
 *
 *   return <>You are signed in</>;
 * }
 * ```
 *
 * @example App Router with options
 *
 * You can customize the authorization request by passing in props. See {@link RedirectToSignInProps}.
 *
 * ```tsx
 * "use client";
 *
 * import { useAuth } from "@monocloud/auth-nextjs/client";
 * import { RedirectToSignIn } from "@monocloud/auth-nextjs/components/client";
 *
 * export default function Home() {
 *   const { isLoading, isAuthenticated } = useAuth();
 *
 *   if (!isLoading && !isAuthenticated) {
 *     return <RedirectToSignIn returnUrl="/dashboard" loginHint="username" />;
 *   }
 *
 *   return <>You are signed in</>;
 * }
 * ```
 *
 * @example Pages Router
 *
 * ```tsx
 * import { useAuth } from "@monocloud/auth-nextjs/client";
 * import { RedirectToSignIn } from "@monocloud/auth-nextjs/components/client";
 *
 * export default function Home() {
 *   const { isLoading, isAuthenticated } = useAuth();
 *
 *   if (!isLoading && !isAuthenticated) {
 *     return <RedirectToSignIn />;
 *   }
 *
 *   return <>You are signed in</>;
 * }
 * ```
 *
 * @example Pages Router with options
 *
 * You can customize the authorization request by passing in props. See {@link RedirectToSignInProps}.
 *
 * ```tsx
 * import { useAuth } from "@monocloud/auth-nextjs/client";
 * import { RedirectToSignIn } from "@monocloud/auth-nextjs/components/client";
 *
 * export default function Home() {
 *   const { isLoading, isAuthenticated } = useAuth();
 *
 *   if (!isLoading && !isAuthenticated) {
 *     return <RedirectToSignIn returnUrl="/dashboard" loginHint="username" />;
 *   }
 *
 *   return <>You are signed in</>;
 * }
 * ```
 */
export const RedirectToSignIn = ({
  returnUrl,
  ...authParams
}: RedirectToSignInProps): null => {
  useEffect(() => {
    redirectToSignIn({ returnUrl, ...authParams });
  }, [authParams, returnUrl]);
  return null;
};
