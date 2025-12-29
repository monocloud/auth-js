import React, { JSX } from 'react';

export interface SignOutProps {
  /** URL to redirect the user to after they have been signed out. */
  postLogoutUrl?: string;

  /** Whether to also sign out the user from MonoCloud */
  federated?: boolean;
}

/**
 * A component that renders an anchor tag configured to initiate the sign-out flow.
 *
 * @param props - Properties for the SignOut component.
 *
 * @returns An anchor element that links to the sign-out endpoint.
 */
export const SignOut = ({
  children,
  postLogoutUrl,
  federated,
  ...props
}: SignOutProps &
  React.AnchorHTMLAttributes<HTMLAnchorElement>): JSX.Element => {
  const signOutUrl =
    process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_SIGNOUT_URL ??
    // eslint-disable-next-line no-underscore-dangle
    `${process.env.__NEXT_ROUTER_BASEPATH ?? ''}/api/auth/signout`;

  const query = new URLSearchParams();

  if (postLogoutUrl) {
    query.set('post_logout_url', postLogoutUrl);
  }

  if (typeof federated === 'boolean') {
    query.set('federated', federated.toString());
  }

  return (
    <a
      href={`${signOutUrl}${query.size ? `?${query.toString()}` : ''}`}
      {...props}
    >
      {children}
    </a>
  );
};
