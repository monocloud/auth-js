'use client';

import { useEffect } from 'react';
import { redirectToSignIn } from '../../client/protect-client-page';
import { ExtraAuthParams } from '../../types';

/**
 * Props for the `<RedirectToSignIn />` Component
 *
 * @category Types
 */
export interface RedirectToSignInProps extends ExtraAuthParams {
  /**
   * The URL to return to after successful authentication. If not provided, the current URL is used.
   */
  returnUrl?: string;
}

/**
 * `<RedirectToSignIn>` is a **client-side component** that immediately redirects the user to the MonoCloud sign-in page when it is rendered.
 *
 * It does not render any UI.
 *
 * > This component must be used inside a Client Component (`"use client"`).
 *
 * @example Basic Usage
 *
 * ```tsx title="Basic Usage"
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
 * @example With Options
 *
 * You can customize the authorization request by passing in props.
 *
 * ```tsx title="With options"
 * "use client";
 *
 * import { useAuth } from "@monocloud/auth-nextjs/client";
 * import { RedirectToSignIn } from "@monocloud/auth-nextjs/components/client";
 *
 * export default function Home() {
 *   const { isLoading, isAuthenticated } = useAuth();
 *
 *   if (!isLoading && !isAuthenticated) {
 *     return (
 *       <RedirectToSignIn
 *         returnUrl="/dashboard"
 *         loginHint="user@example.com"
 *       />
 *     );
 *   }
 *
 *   return <>You are signed in</>;
 * }
 * ```
 *
 * @param props - The props for customizing RedirectToSignIn.
 * @returns
 *
 * @category Components
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
