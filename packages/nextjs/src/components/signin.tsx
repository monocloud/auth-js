import React from 'react';
import { ExtraAuthParams } from '../types';

export interface SignInProps extends ExtraAuthParams {
  children: React.ReactNode;
  /**
   * URL to redirect to after a successful sign-in.
   */
  returnUrl?: string;
}

/**
 * A component that renders an anchor tag configured to initiate the sign-in flow.
 *
 * @param props - Properties for the SignIn component.
 *
 * @returns An anchor element that links to the sign-in endpoint with the specified parameters.
 *
 * @example App Router and Pages Router
 *
 * **Sign-in component works on both the server and the client in pages router and app router.**
 *
 * ```tsx
 * import { SignIn } from "@monocloud/auth-nextjs/components";
 *
 * export default function Home() {
 *   return <SignIn>Sign In</SignIn>;
 * }
 * ```
 *
 * @example Customize the authorization request
 *
 * You can customize the authorization request by passing in props. See {@link SignInProps}.
 *
 * **Note⚠️: You need to set the env `MONOCLOUD_AUTH_ALLOW_QUERY_PARAM_OVERRIDES=true` or `allowQueryParamOverrides` should be `true` in the client initialization for props to work**
 *
 * ```tsx
 * import { SignIn } from "@monocloud/auth-nextjs/components";
 *
 * export default function Home() {
 *   return (
 *     <SignIn loginHint="username" authenticatorHint="password">
 *       Sign In
 *     </SignIn>
 *   );
 * }
 * ```
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
