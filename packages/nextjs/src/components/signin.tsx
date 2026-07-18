import React from 'react';
import { ExtraAuthParams } from '../types';

/**
 * Props for the `<SignIn />` component.
 *
 * @category Types
 */
export interface SignInProps extends ExtraAuthParams {
  /**
   * Content rendered inside the link (for example, button text).
   */
  children: React.ReactNode;

  /**
   * URL to redirect to after successful sign-in.
   */
  returnUrl?: string;
}

/**
 * `<SignIn>` renders a link that initiates the MonoCloud sign-in flow.
 *
 * It can be used in both **App Router** and **Pages Router**, and may be rendered from either **Server** or **Client Components**.
 *
 * @example Basic Usage
 *
 * ```tsx title="Basic Usage"
 * import { SignIn } from "@monocloud/auth-nextjs/components";
 *
 * export default function Home() {
 *   return <SignIn>Sign In</SignIn>;
 * }
 * ```
 *
 * @example Customize the authorization request
 *
 * You can customize the authorization request by passing props:
 *
 * ```tsx title="Customize the authorization request"
 * import { SignIn } from "@monocloud/auth-nextjs/components";
 *
 * export default function Home() {
 *   return (
 *     <SignIn loginHint="user@example.com" authenticatorHint="password" returnUrl="/dashboard">
 *       Sign In
 *     </SignIn>
 *   );
 * }
 * ```
 *
 * @param props - Properties for the SignIn component.
 * @returns An anchor element that links to the sign-in endpoint with the specified parameters.
 *
 * @category Components
 */
export const SignIn = ({
  children,
  authenticatorHint,
  loginHint,
  prompt,
  display,
  uiLocales,
  scopes,
  acrValues,
  resource,
  audience,
  idTokenHint,
  maxAge,
  returnUrl,
  ...props
}: SignInProps &
  Omit<
    React.AnchorHTMLAttributes<HTMLAnchorElement>,
    'resource'
  >): React.ReactNode => {
  const signInUrl =
    process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_SIGNIN_URL ??
    // eslint-disable-next-line no-underscore-dangle
    `${process.env.__NEXT_ROUTER_BASEPATH ?? ''}/api/auth/signin`;

  const query = new URLSearchParams();

  if (authenticatorHint) {
    query.set('authenticator_hint', authenticatorHint);
  }

  if (prompt) {
    query.set('prompt', prompt);
  }

  if (display) {
    query.set('display', display);
  }

  if (uiLocales) {
    query.set('ui_locales', uiLocales);
  }

  if (scopes) {
    query.set('scope', scopes);
  }

  if (acrValues) {
    query.set('acr_values', acrValues.join(' '));
  }

  if (resource) {
    query.set('resource', resource);
  }

  if (audience) {
    query.set('audience', audience);
  }

  if (idTokenHint) {
    query.set('id_token_hint', idTokenHint);
  }

  if (maxAge) {
    query.set('max_age', maxAge.toString());
  }

  if (loginHint) {
    query.set('login_hint', loginHint);
  }

  if (returnUrl) {
    query.set('return_url', returnUrl);
  }

  return (
    <a
      href={`${signInUrl}${query.size ? `?${query.toString()}` : ''}`}
      {...props}
    >
      {children}
    </a>
  );
};
