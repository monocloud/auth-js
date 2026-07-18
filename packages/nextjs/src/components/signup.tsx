import React from 'react';
import { ExtraAuthParams } from '../types';

/**
 * Props for the `<SignUp />` component.
 *
 * @category Types
 */
export interface SignUpProps extends Omit<
  ExtraAuthParams,
  'authenticatorHint' | 'loginHint' | 'prompt'
> {
  /**
   * URL to redirect to after successful sign-up.
   */
  returnUrl?: string;
}

/**
 * `<SignUp>` renders a link that initiates the MonoCloud sign-up flow.
 *
 * It works in both **App Router** and **Pages Router**, and may be rendered from either **Server** or **Client Components**.
 *
 * Internally, it behaves like `<SignIn>` but sets `prompt=create` to start the registration flow.
 *
 * @example Basic usage
 *
 * ```tsx title="Basic Usage"
 * import { SignUp } from "@monocloud/auth-nextjs/components";
 *
 * export default function Home() {
 *   return <SignUp>Sign Up</SignUp>;
 * }
 * ```
 *
 * @example Customize the authorization request
 *
 * You can customize the authorization request by passing in props.
 *
 * ```tsx title="Customize the authorization request"
 * import { SignUp } from "@monocloud/auth-nextjs/components";
 *
 * export default function Home() {
 *   return (
 *     <SignUp
 *       returnUrl="/dashboard"
 *       uiLocales="en"
 *     >
 *       Sign Up
 *     </SignUp>
 *   );
 * }
 * ```
 *
 * @param props - Properties for the SignUp component.
 * @returns An anchor element that links to the sign-in endpoint with the prompt set to 'create'.
 *
 * @category Components
 */
export const SignUp = ({
  children,
  returnUrl,
  acrValues,
  display,
  maxAge,
  resource,
  audience,
  idTokenHint,
  scopes,
  uiLocales,
  ...props
}: SignUpProps &
  Omit<
    React.AnchorHTMLAttributes<HTMLAnchorElement>,
    'resource'
  >): React.ReactNode => {
  const signInUrl =
    process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_SIGNIN_URL ??
    // eslint-disable-next-line no-underscore-dangle
    `${process.env.__NEXT_ROUTER_BASEPATH ?? ''}/api/auth/signin`;

  const query = new URLSearchParams();

  query.set('prompt', 'create');

  if (returnUrl) {
    query.set('return_url', returnUrl);
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

  if (returnUrl) {
    query.set('return_url', returnUrl);
  }

  return (
    <a href={`${signInUrl}?${query.toString()}`} {...props}>
      {children}
    </a>
  );
};
