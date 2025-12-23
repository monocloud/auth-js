import React, { JSX } from 'react';
import { ExtraAuthParams } from '../types';

export interface SignUpProps extends Omit<
  ExtraAuthParams,
  'authenticatorHint' | 'loginHint' | 'prompt'
> {
  /**
   * URL to redirect to after a successful sign-up.
   */
  returnUrl?: string;
}

/**
 * A component that renders an anchor tag configured to initiate the sign-up flow.
 * * It functions similarly to the SignIn component but explicitly sets the `prompt` parameter to `create`.
 *
 * @param props - Properties for the SignUp component.
 *
 * @returns An anchor element that links to the sign-in endpoint with the prompt set to 'create'.
 */
export const SignUp = ({
  children,
  returnUrl,
  acrValues,
  display,
  maxAge,
  resource,
  scopes,
  uiLocales,
  ...props
}: SignUpProps &
  Omit<
    React.AnchorHTMLAttributes<HTMLAnchorElement>,
    'resource'
  >): JSX.Element => {
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
